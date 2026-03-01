#include "node/node.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>

#include "address/address.hpp"
#include "codec/bytes.hpp"
#include "consensus/validators.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "merkle/merkle.hpp"

namespace selfcoin::node {
namespace {

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
  for (int i = 1; i <= 4; ++i) {
    std::array<std::uint8_t, 32> seed{};
    for (size_t j = 0; j < seed.size(); ++j) seed[j] = static_cast<std::uint8_t>(i * 19 + j);
    auto kp = crypto::keypair_from_seed32(seed);
    if (kp.has_value()) out.push_back(*kp);
  }
  return out;
}

bool Node::init() {
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
      for (const auto& kp : keys) {
        validators_.upsert(kp.public_key, consensus::ValidatorInfo{consensus::ValidatorStatus::ACTIVE, 0});
        db_.put_validator(kp.public_key, consensus::ValidatorInfo{consensus::ValidatorStatus::ACTIVE, 0});
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
bool Node::pause_proposals_for_test(bool pause) {
  pause_proposals_ = pause;
  return true;
}

void Node::event_loop() {
  while (running_) {
    std::optional<Block> to_propose;
    {
      std::lock_guard<std::mutex> lk(mu_);
      const std::uint64_t h = finalized_height_ + 1;
      validators_.advance_height(h);
      const auto active = validators_.active_sorted(h);
      const auto leader = consensus::select_leader(finalized_hash_, h, current_round_, active);

      const std::uint64_t now_ms = now_unix() * 1000;
      if (now_ms > round_started_ms_ + ROUND_TIMEOUT_MS) {
        ++current_round_;
        round_started_ms_ = now_ms;
        log_line("round-timeout height=" + std::to_string(h) + " new_round=" + std::to_string(current_round_));
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
        const auto active = validators_.active_sorted(blk->header.height);
        const std::size_t quorum = consensus::quorum_threshold(active.size());
        std::set<PubKey32> seen;
        std::size_t valid_sigs = 0;
        for (const auto& s : blk->finality_proof.sigs) {
          if (!validators_.is_active_for_height(s.validator_pubkey, blk->header.height)) continue;
          if (!seen.insert(s.validator_pubkey).second) continue;
          Bytes bid_bytes(bid.begin(), bid.end());
          if (!crypto::ed25519_verify(bid_bytes, s.signature, s.validator_pubkey)) continue;
          ++valid_sigs;
        }
        if (valid_sigs >= quorum) {
          if (persist_finalized_block(*blk)) {
            apply_block_to_utxo(*blk, utxos_);
            apply_validator_registrations(*blk, blk->header.height);
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

    auto valid = validate_block_txs(*blk, utxos_, BLOCK_REWARD);
    if (!valid.ok) return false;

    Hash32 bid = blk->header.block_id();
    candidate_blocks_[bid] = *blk;

    if (validators_.is_active_for_height(local_key_.public_key, msg.height)) {
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
  if (!validators_.is_active_for_height(vote.validator_pubkey, vote.height)) return false;

  Bytes bid(vote.block_id.begin(), vote.block_id.end());
  if (!crypto::ed25519_verify(bid, vote.signature, vote.validator_pubkey)) return false;

  auto tr = votes_.add_vote(vote);
  if (tr.equivocation && tr.evidence.has_value()) {
    validators_.ban(vote.validator_pubkey);
    db_.put_validator(vote.validator_pubkey, consensus::ValidatorInfo{consensus::ValidatorStatus::BANNED, vote.height});
    log_line("equivocation-banned validator=" + hex_encode(Bytes(vote.validator_pubkey.begin(), vote.validator_pubkey.end())) +
             " height=" + std::to_string(vote.height) + " round=" + std::to_string(vote.round));
  }

  if (!tr.accepted) return tr.duplicate;

  if (from_network) {
    broadcast_vote(vote);
  }

  return finalize_if_quorum(vote.block_id, vote.height, vote.round);
}

bool Node::finalize_if_quorum(const Hash32& block_id, std::uint64_t height, std::uint32_t round) {
  auto blk_it = candidate_blocks_.find(block_id);
  if (blk_it == candidate_blocks_.end()) return false;

  auto sigs = votes_.signatures_for(height, round, block_id);
  const auto active = validators_.active_sorted(height);
  const std::size_t quorum = consensus::quorum_threshold(active.size());
  if (sigs.size() < quorum) return false;

  std::set<PubKey32> seen;
  std::vector<FinalitySig> filtered;
  for (const auto& s : sigs) {
    if (!validators_.is_active_for_height(s.validator_pubkey, height)) continue;
    if (!seen.insert(s.validator_pubkey).second) continue;
    Bytes bid(block_id.begin(), block_id.end());
    if (!crypto::ed25519_verify(bid, s.signature, s.validator_pubkey)) continue;
    filtered.push_back(s);
  }
  if (filtered.size() < quorum) return false;

  Block b = blk_it->second;
  b.finality_proof.sigs = filtered;

  if (!persist_finalized_block(b)) return false;

  apply_block_to_utxo(b, utxos_);
  apply_validator_registrations(b, height);

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
      << " votes=" << filtered.size() << "/" << quorum << " hash=" << hex_encode32(block_id);
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

  const auto pkh = crypto::h160(Bytes(local_key_.public_key.begin(), local_key_.public_key.end()));
  TxOut out;
  out.value = BLOCK_REWARD;
  out.script_pubkey = address::p2pkh_script_pubkey(pkh);
  coinbase.outputs.push_back(out);
  b.txs.push_back(coinbase);

  std::vector<Bytes> tx_bytes;
  tx_bytes.push_back(coinbase.serialize());
  auto m = merkle::compute_merkle_root_from_txs(tx_bytes);
  if (!m.has_value()) return std::nullopt;
  b.header.merkle_root = *m;
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

bool Node::persist_finalized_block(const Block& block) {
  const Hash32 h = block.header.block_id();
  if (!db_.put_block(h, block.serialize())) return false;
  if (!db_.set_height_hash(block.header.height, h)) return false;
  if (!db_.set_tip(storage::TipState{block.header.height, h})) return false;

  // Persist UTXOs for finalized state.
  if (block.txs.size() > 1) {
    for (size_t i = 1; i < block.txs.size(); ++i) {
      for (const auto& in : block.txs[i].inputs) {
        db_.erase_utxo(OutPoint{in.prev_txid, in.prev_index});
      }
    }
  }
  for (const auto& tx : block.txs) {
    const Hash32 txid = tx.txid();
    for (std::uint32_t out_i = 0; out_i < tx.outputs.size(); ++out_i) {
      db_.put_utxo(OutPoint{txid, out_i}, tx.outputs[out_i]);
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

  return true;
}

void Node::apply_validator_registrations(const Block& block, std::uint64_t height) {
  for (const auto& tx : block.txs) {
    for (const auto& out : tx.outputs) {
      PubKey32 pub{};
      if (out.value == BOND_AMOUNT && is_validator_register_script(out.script_pubkey, &pub)) {
        validators_.register_pending(pub, height);
        db_.put_validator(pub, consensus::ValidatorInfo{consensus::ValidatorStatus::PENDING, height});
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
    } else {
      std::cerr << "unknown arg: " << a << "\n";
      return std::nullopt;
    }
  }
  return cfg;
}

}  // namespace selfcoin::node
