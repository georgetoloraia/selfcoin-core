#include "node/node.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <iterator>
#include <set>
#include <sstream>

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "consensus/validators.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "merkle/merkle.hpp"

namespace selfcoin::node {
namespace {

constexpr std::size_t kMaxBlockTxs = 1000;
constexpr std::size_t kMaxBlockBytes = 1 * 1024 * 1024;
constexpr std::uint32_t kTxRatePerSec = 100;

std::string short_pub_hex(const PubKey32& pub) {
  Bytes b(pub.begin(), pub.begin() + 4);
  return hex_encode(b);
}

Bytes make_coinbase_script_sig(std::uint64_t h, std::uint32_t r) {
  std::string msg = "cb:" + std::to_string(h) + ":" + std::to_string(r);
  return Bytes(msg.begin(), msg.end());
}

std::mutex g_local_bus_mu;
std::vector<Node*> g_local_bus_nodes;

}  // namespace

Node::Node(NodeConfig cfg) : cfg_(std::move(cfg)) {
  finalized_hash_ = zero_hash();
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
  if (cfg_.max_committee == 0) cfg_.max_committee = 1;
  if (!db_.open(cfg_.db_path)) {
    std::cerr << "db open failed: " << cfg_.db_path << "\n";
    return false;
  }
  if (!load_state()) {
    std::cerr << "load_state failed\n";
    return false;
  }

  if (cfg_.devnet) {
    const auto keys = devnet_keypairs();
    if (cfg_.node_id < 0 || cfg_.node_id >= static_cast<int>(keys.size())) {
      std::cerr << "invalid node_id " << cfg_.node_id << "\n";
      return false;
    }
    local_key_ = keys[cfg_.node_id];

    if (validators_.all().empty()) {
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

  if (!cfg_.disable_p2p) {
    p2p_.set_on_message([this](int peer_id, std::uint16_t msg_type, const Bytes& payload) {
      handle_message(peer_id, msg_type, payload);
    });
    if (!p2p_.start_listener(cfg_.bind_ip, cfg_.p2p_port)) {
      std::cerr << "listener start failed " << cfg_.bind_ip << ":" << cfg_.p2p_port << "\n";
      return false;
    }
    for (const auto& peer : cfg_.peers) {
      const auto pos = peer.find(':');
      if (pos == std::string::npos) continue;
      const std::string host = peer.substr(0, pos);
      const std::uint16_t port = static_cast<std::uint16_t>(std::stoi(peer.substr(pos + 1)));
      if (p2p_.connect_to(host, port)) {
        for (int pid : p2p_.peer_ids()) {
          send_version(pid);
        }
      }
    }
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
  if (!running_.exchange(false)) return;
  if (loop_thread_.joinable()) loop_thread_.join();
  p2p_.stop();
  if (cfg_.disable_p2p) {
    std::lock_guard<std::mutex> lk(g_local_bus_mu);
    g_local_bus_nodes.erase(std::remove(g_local_bus_nodes.begin(), g_local_bus_nodes.end(), this), g_local_bus_nodes.end());
  }
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
  return s;
}

bool Node::inject_vote_for_test(const Vote& vote) { return handle_vote(vote, false); }
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
  pause_proposals_ = pause;
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
      if (now_ms > round_started_ms_ + ROUND_TIMEOUT_MS) {
        ++current_round_;
        round_started_ms_ = now_ms;
        log_line("round-timeout height=" + std::to_string(h) + " new_round=" + std::to_string(current_round_));
      }

      const auto hr = std::make_pair(h, current_round_);
      if (logged_committee_rounds_.insert(hr).second) {
        std::ostringstream coss;
        coss << "committee height=" << h << " round=" << current_round_ << " size=" << committee.size()
             << " quorum=" << quorum << " members=";
        for (std::size_t i = 0; i < committee.size(); ++i) {
          if (i) coss << ",";
          coss << short_pub_hex(committee[i]);
        }
        log_line(coss.str());
      }

      if (!pause_proposals_ && leader.has_value() && *leader == local_key_.public_key) {
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
  }
}

void Node::send_version(int peer_id) {
  auto tip = db_.get_tip();
  p2p::VersionMsg v;
  v.timestamp = now_unix();
  v.nonce = static_cast<std::uint32_t>(cfg_.node_id + 1000);
  v.start_height = tip ? tip->height : 0;
  v.start_hash = tip ? tip->hash : zero_hash();

  p2p_.send_to(peer_id, p2p::MsgType::VERSION, p2p::ser_version(v));
  p2p_.mark_handshake_tx(peer_id, true, false);
}

void Node::maybe_send_verack(int peer_id) {
  p2p_.send_to(peer_id, p2p::MsgType::VERACK, {});
  p2p_.mark_handshake_tx(peer_id, false, true);
}

void Node::handle_message(int peer_id, std::uint16_t msg_type, const Bytes& payload) {
  if (msg_type == p2p::MsgType::VERSION) {
    auto v = p2p::de_version(payload);
    if (!v.has_value() || v->proto_version != PROTOCOL_VERSION) return;
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
  if (!info.established()) return;

  switch (msg_type) {
    case p2p::MsgType::GET_FINALIZED_TIP: {
      p2p::FinalizedTipMsg tip{finalized_height_, finalized_hash_};
      p2p_.send_to(peer_id, p2p::MsgType::FINALIZED_TIP, p2p::ser_finalized_tip(tip));
      break;
    }
    case p2p::MsgType::FINALIZED_TIP: {
      auto tip = p2p::de_finalized_tip(payload);
      if (!tip.has_value()) return;
      if (tip->height > finalized_height_) {
        auto req = p2p::GetBlockMsg{tip->hash};
        p2p_.send_to(peer_id, p2p::MsgType::GET_BLOCK, p2p::ser_get_block(req));
      }
      break;
    }
    case p2p::MsgType::GET_BLOCK: {
      auto gb = p2p::de_get_block(payload);
      if (!gb.has_value()) return;
      auto blk = db_.get_block(gb->hash);
      if (!blk.has_value()) return;
      p2p_.send_to(peer_id, p2p::MsgType::BLOCK, p2p::ser_block(p2p::BlockMsg{*blk}));
      break;
    }
    case p2p::MsgType::BLOCK: {
      auto b = p2p::de_block(payload);
      if (!b.has_value()) return;
      auto blk = Block::parse(b->block_bytes);
      if (!blk.has_value()) return;
      std::lock_guard<std::mutex> lk(mu_);
      if (blk->header.height == finalized_height_ + 1 && blk->header.prev_finalized_hash == finalized_hash_) {
        const auto bid = blk->header.block_id();
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
            votes_.clear_height(blk->header.height);
            candidate_blocks_.clear();
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
      if (!p.has_value()) return;
      handle_propose(*p, true);
      break;
    }
    case p2p::MsgType::VOTE: {
      auto v = p2p::de_vote(payload);
      if (!v.has_value()) return;
      handle_vote(v->vote, true);
      break;
    }
    case p2p::MsgType::TX: {
      const std::uint64_t now = now_unix();
      auto& r = tx_rate_state_[peer_id];
      if (r.first != now) {
        r.first = now;
        r.second = 0;
      }
      if (++r.second > kTxRatePerSec) {
        return;
      }
      auto m = p2p::de_tx(payload);
      if (!m.has_value()) return;
      auto tx = Tx::parse(m->tx_bytes);
      if (!tx.has_value()) return;
      handle_tx(*tx, true, peer_id);
      break;
    }
    default:
      break;
  }
}

bool Node::handle_propose(const p2p::ProposeMsg& msg, bool from_network) {
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
    auto valid = validate_block_txs(*blk, utxos_, BLOCK_REWARD, &vctx);
    if (!valid.ok) return false;

    Hash32 bid = blk->header.block_id();
    candidate_blocks_[bid] = *blk;

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

bool Node::handle_vote(const Vote& vote, bool from_network) {
  std::lock_guard<std::mutex> lk(mu_);
  if (vote.height != finalized_height_ + 1) return false;
  if (!is_committee_member_for(vote.validator_pubkey, vote.height, vote.round)) return false;

  Bytes bid(vote.block_id.begin(), vote.block_id.end());
  if (!crypto::ed25519_verify(bid, vote.signature, vote.validator_pubkey)) return false;

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

  if (!tr.accepted) return tr.duplicate;

  if (from_network) {
    broadcast_vote(vote);
  }

  return finalize_if_quorum(vote.block_id, vote.height, vote.round);
}

bool Node::handle_tx(const Tx& tx, bool from_network, int from_peer_id) {
  Hash32 txid{};
  {
    std::lock_guard<std::mutex> lk(mu_);
    mempool_.set_validation_context(
        SpecialValidationContext{&validators_, finalized_height_ + 1,
                                 [this](const PubKey32& pub, std::uint64_t h, std::uint32_t round) {
                                   return is_committee_member_for(pub, h, round);
                                 }});
    std::string err;
    if (!mempool_.accept_tx(tx, utxos_, &err)) {
      return false;
    }
    txid = tx.txid();
    log_line("mempool-accept txid=" + hex_encode32(txid) + " mempool_size=" + std::to_string(mempool_.size()));
  }

  if (from_network) broadcast_tx(tx, from_peer_id);
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

  votes_.clear_height(height);
  candidate_blocks_.clear();

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

  const auto pkh = crypto::h160(Bytes(local_key_.public_key.begin(), local_key_.public_key.end()));
  TxOut out;
  out.value = BLOCK_REWARD + total_fees;
  out.script_pubkey = address::p2pkh_script_pubkey(pkh);
  coinbase.outputs.push_back(out);
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
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      std::thread([peer, p]() { peer->handle_propose(p, true); }).detach();
    }
  } else {
    p2p_.broadcast(p2p::MsgType::PROPOSE, p2p::ser_propose(p));
  }
}

void Node::broadcast_vote(const Vote& vote) {
  if (cfg_.disable_p2p) {
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      std::thread([peer, vote]() { peer->handle_vote(vote, true); }).detach();
    }
  } else {
    p2p_.broadcast(p2p::MsgType::VOTE, p2p::ser_vote(p2p::VoteMsg{vote}));
  }
}

void Node::broadcast_finalized_block(const Block& block) {
  if (cfg_.disable_p2p) {
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      std::thread([peer, block]() {
        p2p::ProposeMsg pm{block.header.height, block.header.round, block.header.prev_finalized_hash, block.serialize()};
        peer->handle_propose(pm, true);
      }).detach();
    }
  } else {
    p2p_.broadcast(p2p::MsgType::BLOCK, p2p::ser_block(p2p::BlockMsg{block.serialize()}));
  }
}

void Node::broadcast_tx(const Tx& tx, int skip_peer_id) {
  if (cfg_.disable_p2p) {
    std::vector<Node*> peers;
    {
      std::lock_guard<std::mutex> lk(g_local_bus_mu);
      peers = g_local_bus_nodes;
    }
    for (Node* peer : peers) {
      if (peer == this) continue;
      std::thread([peer, tx]() { peer->handle_tx(tx, true); }).detach();
    }
  } else {
    const auto payload = p2p::ser_tx(p2p::TxMsg{tx.serialize()});
    for (int id : p2p_.peer_ids()) {
      if (id == skip_peer_id) continue;
      p2p_.send_to(id, p2p::MsgType::TX, payload);
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
  return true;
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

  if (cfg_.devnet) {
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

void Node::log_line(const std::string& s) const {
  std::cout << "[node " << cfg_.node_id << "] " << s << "\n";
}

std::optional<NodeConfig> parse_args(int argc, char** argv) {
  NodeConfig cfg;

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
    } else if (a == "--node-id") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.node_id = std::stoi(*v);
    } else if (a == "--port") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.p2p_port = static_cast<std::uint16_t>(std::stoi(*v));
    } else if (a == "--db") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.db_path = *v;
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
    } else if (a == "--devnet-initial-active") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.devnet_initial_active_validators = std::stoi(*v);
    } else if (a == "--max-committee") {
      auto v = next(a);
      if (!v) return std::nullopt;
      cfg.max_committee = static_cast<std::size_t>(std::stoull(*v));
    } else {
      std::cerr << "unknown arg: " << a << "\n";
      return std::nullopt;
    }
  }
  return cfg;
}

}  // namespace selfcoin::node
