#include "storage/db.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>

#include "codec/bytes.hpp"
#include "common/paths.hpp"

#ifdef SC_HAS_ROCKSDB
#include <rocksdb/db.h>
#endif

namespace selfcoin::storage {

namespace {

Bytes serialize_tip(const TipState& tip) {
  codec::ByteWriter w;
  w.u64le(tip.height);
  w.bytes_fixed(tip.hash);
  return w.take();
}

std::optional<TipState> parse_tip(const Bytes& b) {
  TipState t;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto hash = r.bytes_fixed<32>();
        if (!h || !hash) return false;
        t.height = *h;
        t.hash = *hash;
        return true;
      })) {
    return std::nullopt;
  }
  return t;
}

Bytes serialize_outpoint(const OutPoint& op) {
  codec::ByteWriter w;
  w.bytes_fixed(op.txid);
  w.u32le(op.index);
  return w.take();
}

std::optional<OutPoint> parse_outpoint(const Bytes& b) {
  OutPoint op;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto tx = r.bytes_fixed<32>();
        auto idx = r.u32le();
        if (!tx || !idx) return false;
        op.txid = *tx;
        op.index = *idx;
        return true;
      })) {
    return std::nullopt;
  }
  return op;
}

Bytes serialize_txout(const TxOut& out) {
  codec::ByteWriter w;
  w.u64le(out.value);
  w.varbytes(out.script_pubkey);
  return w.take();
}

std::optional<TxOut> parse_txout(const Bytes& b) {
  TxOut out;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto v = r.u64le();
        auto s = r.varbytes();
        if (!v || !s) return false;
        out.value = *v;
        out.script_pubkey = *s;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Bytes serialize_validator(const consensus::ValidatorInfo& info) {
  codec::ByteWriter w;
  w.u8(static_cast<std::uint8_t>(info.status));
  w.u64le(info.joined_height);
  w.u8(info.has_bond ? 1 : 0);
  w.bytes_fixed(info.bond_outpoint.txid);
  w.u32le(info.bond_outpoint.index);
  w.u64le(info.unbond_height);
  w.u64le(info.eligible_count_window);
  w.u64le(info.participated_count_window);
  w.u64le(info.liveness_window_start);
  w.u64le(info.suspended_until_height);
  w.u64le(info.last_join_height);
  w.u64le(info.last_exit_height);
  w.u32le(info.penalty_strikes);
  w.u64le(info.bonded_amount);
  return w.take();
}

std::optional<consensus::ValidatorInfo> parse_validator(const Bytes& b) {
  consensus::ValidatorInfo info;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto st = r.u8();
        auto h = r.u64le();
        if (!st || !h) return false;
        info.status = static_cast<consensus::ValidatorStatus>(*st);
        info.joined_height = *h;
        if (r.eof()) {
          // Backward compatibility for v0 records.
          info.bonded_amount = BOND_AMOUNT;
          info.has_bond = true;
          info.unbond_height = 0;
          return true;
        }
        auto has_bond = r.u8();
        auto txid = r.bytes_fixed<32>();
        auto idx = r.u32le();
        auto unbond = r.u64le();
        if (!has_bond || !txid || !idx || !unbond) return false;
        info.has_bond = (*has_bond != 0);
        info.bond_outpoint = OutPoint{*txid, *idx};
        info.unbond_height = *unbond;
        if (r.eof()) return true;
        auto eligible = r.u64le();
        auto participated = r.u64le();
        auto lstart = r.u64le();
        auto suspended = r.u64le();
        auto last_join = r.u64le();
        auto last_exit = r.u64le();
        auto strikes = r.u32le();
        if (!eligible || !participated || !lstart || !suspended || !last_join || !last_exit || !strikes) return false;
        info.eligible_count_window = *eligible;
        info.participated_count_window = *participated;
        info.liveness_window_start = *lstart;
        info.suspended_until_height = *suspended;
        info.last_join_height = *last_join;
        info.last_exit_height = *last_exit;
        info.penalty_strikes = *strikes;
        if (!r.eof()) {
          auto bonded = r.u64le();
          if (!bonded || !r.eof()) return false;
          info.bonded_amount = *bonded;
        } else {
          info.bonded_amount = BOND_AMOUNT;
        }
        return true;
      })) {
    return std::nullopt;
  }
  return info;
}

Bytes serialize_validator_join_request(const ValidatorJoinRequest& req) {
  codec::ByteWriter w;
  w.bytes_fixed(req.request_txid);
  w.bytes_fixed(req.validator_pubkey);
  w.bytes_fixed(req.payout_pubkey);
  w.bytes_fixed(req.bond_outpoint.txid);
  w.u32le(req.bond_outpoint.index);
  w.u64le(req.bond_amount);
  w.u64le(req.requested_height);
  w.u64le(req.approved_height);
  w.u8(static_cast<std::uint8_t>(req.status));
  return w.take();
}

std::optional<ValidatorJoinRequest> parse_validator_join_request(const Bytes& b) {
  ValidatorJoinRequest req;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto request_txid = r.bytes_fixed<32>();
        auto validator_pub = r.bytes_fixed<32>();
        auto payout_pub = r.bytes_fixed<32>();
        auto bond_txid = r.bytes_fixed<32>();
        auto bond_index = r.u32le();
        auto bond_amount = r.u64le();
        auto requested_height = r.u64le();
        auto approved_height = r.u64le();
        auto status = r.u8();
        if (!request_txid || !validator_pub || !payout_pub || !bond_txid || !bond_index || !bond_amount ||
            !requested_height || !approved_height || !status) {
          return false;
        }
        req.request_txid = *request_txid;
        req.validator_pubkey = *validator_pub;
        req.payout_pubkey = *payout_pub;
        req.bond_outpoint = OutPoint{*bond_txid, *bond_index};
        req.bond_amount = *bond_amount;
        req.requested_height = *requested_height;
        req.approved_height = *approved_height;
        req.status = static_cast<ValidatorJoinRequestStatus>(*status);
        return true;
      })) {
    return std::nullopt;
  }
  return req;
}

Bytes serialize_slashing_record(const SlashingRecord& rec) {
  codec::ByteWriter w;
  w.bytes_fixed(rec.record_id);
  w.u8(static_cast<std::uint8_t>(rec.kind));
  w.bytes_fixed(rec.validator_pubkey);
  w.u64le(rec.height);
  w.u32le(rec.round);
  w.u64le(rec.observed_height);
  w.bytes_fixed(rec.object_a);
  w.bytes_fixed(rec.object_b);
  w.bytes_fixed(rec.txid);
  return w.take();
}

std::optional<SlashingRecord> parse_slashing_record(const Bytes& b) {
  SlashingRecord rec;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto rid = r.bytes_fixed<32>();
        auto kind = r.u8();
        auto pub = r.bytes_fixed<32>();
        auto height = r.u64le();
        auto round = r.u32le();
        auto observed = r.u64le();
        auto a = r.bytes_fixed<32>();
        auto c = r.bytes_fixed<32>();
        auto txid = r.bytes_fixed<32>();
        if (!rid || !kind || !pub || !height || !round || !observed || !a || !c || !txid) return false;
        rec.record_id = *rid;
        rec.kind = static_cast<SlashingRecordKind>(*kind);
        rec.validator_pubkey = *pub;
        rec.height = *height;
        rec.round = *round;
        rec.observed_height = *observed;
        rec.object_a = *a;
        rec.object_b = *c;
        rec.txid = *txid;
        return true;
      })) {
    return std::nullopt;
  }
  return rec;
}

Bytes serialize_committee_epoch_snapshot(const CommitteeEpochSnapshot& snapshot) {
  codec::ByteWriter w;
  w.u64le(snapshot.epoch_start_height);
  w.bytes_fixed(snapshot.epoch_seed);
  w.varint(snapshot.ordered_members.size());
  for (const auto& member : snapshot.ordered_members) w.bytes_fixed(member);
  return w.take();
}

std::optional<CommitteeEpochSnapshot> parse_committee_epoch_snapshot(const Bytes& b) {
  CommitteeEpochSnapshot snapshot;
  if (!codec::parse_exact(b, [&](codec::ByteReader& r) {
        auto epoch_start = r.u64le();
        auto seed = r.bytes_fixed<32>();
        auto count = r.varint();
        if (!epoch_start || !seed || !count) return false;
        snapshot.epoch_start_height = *epoch_start;
        snapshot.epoch_seed = *seed;
        snapshot.ordered_members.clear();
        snapshot.ordered_members.reserve(*count);
        for (std::uint64_t i = 0; i < *count; ++i) {
          auto member = r.bytes_fixed<32>();
          if (!member) return false;
          snapshot.ordered_members.push_back(*member);
        }
        return true;
      })) {
    return std::nullopt;
  }
  return snapshot;
}

Bytes u64be_bytes(std::uint64_t v) {
  Bytes out(8);
  for (int i = 7; i >= 0; --i) {
    out[7 - i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
  }
  return out;
}

}  // namespace

std::string key_block(const Hash32& hash) { return "B:" + hex_encode(Bytes(hash.begin(), hash.end())); }
std::string key_finality_certificate_height(std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return "FC:H:" + hex_encode(w.data());
}
std::string key_finality_certificate_block(const Hash32& hash) {
  return "FC:B:" + hex_encode(Bytes(hash.begin(), hash.end()));
}
std::string key_height(std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return "H:" + hex_encode(w.data());
}
std::string key_utxo(const OutPoint& op) { return "U:" + hex_encode(serialize_outpoint(op)); }
std::string key_validator(const PubKey32& pub) { return "V:" + hex_encode(Bytes(pub.begin(), pub.end())); }
std::string key_validator_join_request(const Hash32& request_txid) {
  return "VJR:" + hex_encode(Bytes(request_txid.begin(), request_txid.end()));
}
std::string key_slashing_record(const Hash32& record_id) {
  return "SL:" + hex_encode(Bytes(record_id.begin(), record_id.end()));
}
std::string key_committee_epoch_snapshot(std::uint64_t epoch_start_height) {
  codec::ByteWriter w;
  w.u64le(epoch_start_height);
  return "CE:" + hex_encode(w.data());
}
std::string key_txidx(const Hash32& txid) { return "X:" + hex_encode(Bytes(txid.begin(), txid.end())); }
std::string key_su_prefix(const Hash32& scripthash) {
  return "SU:" + hex_encode(Bytes(scripthash.begin(), scripthash.end())) + ":";
}
std::string key_su(const Hash32& scripthash, const OutPoint& op) {
  return key_su_prefix(scripthash) + hex_encode(serialize_outpoint(op));
}
std::string key_sh_prefix(const Hash32& scripthash) {
  return "SH:" + hex_encode(Bytes(scripthash.begin(), scripthash.end())) + ":";
}
std::string key_sh(const Hash32& scripthash, std::uint64_t height, const Hash32& txid) {
  return key_sh_prefix(scripthash) + hex_encode(u64be_bytes(height)) + ":" + hex_encode(Bytes(txid.begin(), txid.end()));
}

#ifdef SC_HAS_ROCKSDB
class DB::RocksImpl {
 public:
  std::unique_ptr<rocksdb::DB> db;
};
#endif

DB::DB() = default;
DB::~DB() = default;

bool DB::open(const std::string& path) {
  path_ = expand_user_home(path);
  (void)ensure_private_dir(path_);
  readonly_ = false;
#ifdef SC_HAS_ROCKSDB
  std::error_code ec;
  std::filesystem::create_directories(path_, ec);
  rocks_ = std::make_unique<RocksImpl>();
  rocksdb::Options options;
  options.create_if_missing = true;
  rocksdb::DB* raw = nullptr;
  auto s = rocksdb::DB::Open(options, path_, &raw);
  if (!s.ok()) return false;
  rocks_->db.reset(raw);
  return true;
#else
  std::error_code ec;
  std::filesystem::create_directories(path_, ec);
  return load_file();
#endif
}

bool DB::open_readonly(const std::string& path) {
  path_ = expand_user_home(path);
  (void)ensure_private_dir(path_);
  readonly_ = true;
#ifdef SC_HAS_ROCKSDB
  std::error_code ec;
  std::filesystem::create_directories(path_, ec);
  rocks_ = std::make_unique<RocksImpl>();
  rocksdb::Options options;
  options.create_if_missing = false;
  rocksdb::DB* raw = nullptr;
  auto s = rocksdb::DB::OpenForReadOnly(options, path_, &raw);
  if (!s.ok()) return false;
  rocks_->db.reset(raw);
  return true;
#else
  std::error_code ec;
  std::filesystem::create_directories(path_, ec);
  return load_file();
#endif
}

bool DB::put(const std::string& key, const Bytes& value) {
  if (readonly_) return false;
#ifdef SC_HAS_ROCKSDB
  auto s = rocks_->db->Put(rocksdb::WriteOptions(), key, rocksdb::Slice(reinterpret_cast<const char*>(value.data()), value.size()));
  return s.ok();
#else
  mem_[key] = value;
  return flush_file();
#endif
}

std::optional<Bytes> DB::get(const std::string& key) const {
#ifdef SC_HAS_ROCKSDB
  std::string v;
  auto s = rocks_->db->Get(rocksdb::ReadOptions(), key, &v);
  if (!s.ok()) return std::nullopt;
  return Bytes(v.begin(), v.end());
#else
  auto it = mem_.find(key);
  if (it == mem_.end()) return std::nullopt;
  return it->second;
#endif
}

std::map<std::string, Bytes> DB::scan_prefix(const std::string& prefix) const {
  std::map<std::string, Bytes> out;
#ifdef SC_HAS_ROCKSDB
  std::unique_ptr<rocksdb::Iterator> it(rocks_->db->NewIterator(rocksdb::ReadOptions()));
  for (it->Seek(prefix); it->Valid(); it->Next()) {
    std::string k = it->key().ToString();
    if (k.rfind(prefix, 0) != 0) break;
    out[k] = Bytes(it->value().data(), it->value().data() + it->value().size());
  }
#else
  for (const auto& [k, v] : mem_) {
    if (k.rfind(prefix, 0) == 0) out[k] = v;
  }
#endif
  return out;
}

bool DB::set_tip(const TipState& tip) { return put("T:", serialize_tip(tip)); }

std::optional<TipState> DB::get_tip() const {
  auto b = get("T:");
  if (!b.has_value()) return std::nullopt;
  return parse_tip(*b);
}

bool DB::put_block(const Hash32& hash, const Bytes& block_bytes) { return put(key_block(hash), block_bytes); }
std::optional<Bytes> DB::get_block(const Hash32& hash) const { return get(key_block(hash)); }

bool DB::put_finality_certificate(const FinalityCertificate& cert) {
  const Bytes bytes = cert.serialize();
  return put(key_finality_certificate_height(cert.height), bytes) &&
         put(key_finality_certificate_block(cert.block_id), bytes);
}

std::optional<FinalityCertificate> DB::get_finality_certificate_by_height(std::uint64_t height) const {
  auto b = get(key_finality_certificate_height(height));
  if (!b.has_value()) return std::nullopt;
  return FinalityCertificate::parse(*b);
}

std::optional<FinalityCertificate> DB::get_finality_certificate_by_block(const Hash32& hash) const {
  auto b = get(key_finality_certificate_block(hash));
  if (!b.has_value()) return std::nullopt;
  return FinalityCertificate::parse(*b);
}

bool DB::set_height_hash(std::uint64_t height, const Hash32& hash) {
  return put(key_height(height), Bytes(hash.begin(), hash.end()));
}

std::optional<Hash32> DB::get_height_hash(std::uint64_t height) const {
  auto b = get(key_height(height));
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  Hash32 h{};
  std::copy(b->begin(), b->end(), h.begin());
  return h;
}

bool DB::put_utxo(const OutPoint& op, const TxOut& out) { return put(key_utxo(op), serialize_txout(out)); }
bool DB::erase_utxo(const OutPoint& op) {
  if (readonly_) return false;
#ifdef SC_HAS_ROCKSDB
  auto s = rocks_->db->Delete(rocksdb::WriteOptions(), key_utxo(op));
  return s.ok();
#else
  mem_.erase(key_utxo(op));
  return flush_file();
#endif
}

std::map<OutPoint, UtxoEntry> DB::load_utxos() const {
  std::map<OutPoint, UtxoEntry> out;
  for (const auto& [k, v] : scan_prefix("U:")) {
    auto op_hex = k.substr(2);
    auto op_b = hex_decode(op_hex);
    if (!op_b.has_value()) continue;
    auto op = parse_outpoint(*op_b);
    auto txout = parse_txout(v);
    if (!op.has_value() || !txout.has_value()) continue;
    out[*op] = UtxoEntry{*txout};
  }
  return out;
}

bool DB::put_validator(const PubKey32& pub, const consensus::ValidatorInfo& info) {
  return put(key_validator(pub), serialize_validator(info));
}

std::map<PubKey32, consensus::ValidatorInfo> DB::load_validators() const {
  std::map<PubKey32, consensus::ValidatorInfo> out;
  for (const auto& [k, v] : scan_prefix("V:")) {
    auto hex = k.substr(2);
    auto b = hex_decode(hex);
    auto info = parse_validator(v);
    if (!b.has_value() || b->size() != 32 || !info.has_value()) continue;
    PubKey32 pub{};
    std::copy(b->begin(), b->end(), pub.begin());
    out[pub] = *info;
  }
  return out;
}

bool DB::put_validator_join_request(const Hash32& request_txid, const ValidatorJoinRequest& req) {
  return put(key_validator_join_request(request_txid), serialize_validator_join_request(req));
}

std::map<Hash32, ValidatorJoinRequest> DB::load_validator_join_requests() const {
  std::map<Hash32, ValidatorJoinRequest> out;
  for (const auto& [k, v] : scan_prefix("VJR:")) {
    auto hex = k.substr(4);
    auto b = hex_decode(hex);
    auto req = parse_validator_join_request(v);
    if (!b.has_value() || b->size() != 32 || !req.has_value()) continue;
    Hash32 request_txid{};
    std::copy(b->begin(), b->end(), request_txid.begin());
    out[request_txid] = *req;
  }
  return out;
}

bool DB::put_slashing_record(const SlashingRecord& rec) {
  return put(key_slashing_record(rec.record_id), serialize_slashing_record(rec));
}

std::map<Hash32, SlashingRecord> DB::load_slashing_records() const {
  std::map<Hash32, SlashingRecord> out;
  for (const auto& [k, v] : scan_prefix("SL:")) {
    auto rec = parse_slashing_record(v);
    if (!rec.has_value()) continue;
    out[rec->record_id] = *rec;
  }
  return out;
}

bool DB::put_committee_epoch_snapshot(const CommitteeEpochSnapshot& snapshot) {
  return put(key_committee_epoch_snapshot(snapshot.epoch_start_height), serialize_committee_epoch_snapshot(snapshot));
}

std::optional<CommitteeEpochSnapshot> DB::get_committee_epoch_snapshot(std::uint64_t epoch_start_height) const {
  auto b = get(key_committee_epoch_snapshot(epoch_start_height));
  if (!b.has_value()) return std::nullopt;
  return parse_committee_epoch_snapshot(*b);
}

std::map<std::uint64_t, CommitteeEpochSnapshot> DB::load_committee_epoch_snapshots() const {
  std::map<std::uint64_t, CommitteeEpochSnapshot> out;
  for (const auto& [_, v] : scan_prefix("CE:")) {
    auto snapshot = parse_committee_epoch_snapshot(v);
    if (!snapshot.has_value()) continue;
    out[snapshot->epoch_start_height] = *snapshot;
  }
  return out;
}

bool DB::put_tx_index(const Hash32& txid, std::uint64_t height, std::uint32_t tx_index, const Bytes& tx_bytes) {
  codec::ByteWriter w;
  w.u64le(height);
  w.u32le(tx_index);
  w.varbytes(tx_bytes);
  return put(key_txidx(txid), w.take());
}

std::optional<DB::TxLocation> DB::get_tx_index(const Hash32& txid) const {
  auto b = get(key_txidx(txid));
  if (!b.has_value()) return std::nullopt;
  TxLocation out;
  if (!codec::parse_exact(*b, [&](codec::ByteReader& r) {
        auto h = r.u64le();
        auto i = r.u32le();
        auto tx = r.varbytes();
        if (!h || !i || !tx) return false;
        out.height = *h;
        out.tx_index = *i;
        out.tx_bytes = *tx;
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

bool DB::put_script_utxo(const Hash32& scripthash, const OutPoint& op, const TxOut& out, std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  w.u64le(out.value);
  w.varbytes(out.script_pubkey);
  return put(key_su(scripthash, op), w.take());
}

bool DB::erase_script_utxo(const Hash32& scripthash, const OutPoint& op) {
  if (readonly_) return false;
#ifdef SC_HAS_ROCKSDB
  auto s = rocks_->db->Delete(rocksdb::WriteOptions(), key_su(scripthash, op));
  return s.ok();
#else
  mem_.erase(key_su(scripthash, op));
  return flush_file();
#endif
}

std::vector<DB::ScriptUtxoEntry> DB::get_script_utxos(const Hash32& scripthash) const {
  std::vector<ScriptUtxoEntry> out;
  const std::string prefix = key_su_prefix(scripthash);
  for (const auto& [k, v] : scan_prefix(prefix)) {
    const std::string op_hex = k.substr(prefix.size());
    auto op_b = hex_decode(op_hex);
    if (!op_b.has_value()) continue;
    auto op = parse_outpoint(*op_b);
    if (!op.has_value()) continue;

    ScriptUtxoEntry e;
    e.outpoint = *op;
    if (!codec::parse_exact(v, [&](codec::ByteReader& r) {
          auto h = r.u64le();
          auto val = r.u64le();
          auto spk = r.varbytes();
          if (!h || !val || !spk) return false;
          e.height = *h;
          e.value = *val;
          e.script_pubkey = *spk;
          return true;
        })) {
      continue;
    }
    out.push_back(std::move(e));
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    if (a.height != b.height) return a.height < b.height;
    return std::tie(a.outpoint.txid, a.outpoint.index) < std::tie(b.outpoint.txid, b.outpoint.index);
  });
  return out;
}

bool DB::add_script_history(const Hash32& scripthash, std::uint64_t height, const Hash32& txid) {
  return put(key_sh(scripthash, height, txid), {});
}

bool DB::flush() {
#ifdef SC_HAS_ROCKSDB
  if (!rocks_ || !rocks_->db) return false;
  rocksdb::FlushOptions opts;
  opts.wait = true;
  auto s = rocks_->db->Flush(opts);
  return s.ok();
#else
  return flush_file();
#endif
}

void DB::close() {
#ifdef SC_HAS_ROCKSDB
  rocks_.reset();
#else
  mem_.clear();
#endif
}

std::vector<DB::ScriptHistoryEntry> DB::get_script_history(const Hash32& scripthash) const {
  std::vector<ScriptHistoryEntry> out;
  const std::string prefix = key_sh_prefix(scripthash);
  for (const auto& [k, _] : scan_prefix(prefix)) {
    const std::string rest = k.substr(prefix.size());
    const auto pos = rest.find(':');
    if (pos == std::string::npos) continue;
    const std::string h_hex = rest.substr(0, pos);
    const std::string txid_hex = rest.substr(pos + 1);
    auto hb = hex_decode(h_hex);
    auto tb = hex_decode(txid_hex);
    if (!hb.has_value() || hb->size() != 8 || !tb.has_value() || tb->size() != 32) continue;

    std::uint64_t height = 0;
    for (size_t i = 0; i < 8; ++i) {
      height = (height << 8) | (*hb)[i];
    }
    Hash32 txid{};
    std::copy(tb->begin(), tb->end(), txid.begin());
    out.push_back(ScriptHistoryEntry{txid, height});
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    if (a.height != b.height) return a.height < b.height;
    return a.txid < b.txid;
  });
  return out;
}

#ifndef SC_HAS_ROCKSDB
bool DB::flush_file() const {
  codec::ByteWriter w;
  w.varint(mem_.size());
  for (const auto& [k, v] : mem_) {
    w.varbytes(Bytes(k.begin(), k.end()));
    w.varbytes(v);
  }
  std::ofstream f(path_ + "/kv.bin", std::ios::binary | std::ios::trunc);
  if (!f.good()) return false;
  const auto& d = w.data();
  f.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(d.size()));
  return f.good();
}

bool DB::load_file() {
  mem_.clear();
  std::ifstream f(path_ + "/kv.bin", std::ios::binary);
  if (!f.good()) return true;
  std::vector<char> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  Bytes b(raw.begin(), raw.end());
  codec::ByteReader r(b);
  auto n = r.varint();
  if (!n.has_value()) return false;
  for (std::uint64_t i = 0; i < *n; ++i) {
    auto k = r.varbytes();
    auto v = r.varbytes();
    if (!k || !v) return false;
    mem_[std::string(k->begin(), k->end())] = *v;
  }
  return r.eof();
}
#endif

}  // namespace selfcoin::storage
