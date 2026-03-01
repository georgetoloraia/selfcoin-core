#include "storage/db.hpp"

#include <filesystem>
#include <fstream>
#include <memory>

#include "codec/bytes.hpp"

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
        return true;
      })) {
    return std::nullopt;
  }
  return info;
}

}  // namespace

std::string key_block(const Hash32& hash) { return "B:" + hex_encode(Bytes(hash.begin(), hash.end())); }
std::string key_height(std::uint64_t height) {
  codec::ByteWriter w;
  w.u64le(height);
  return "H:" + hex_encode(w.data());
}
std::string key_utxo(const OutPoint& op) { return "U:" + hex_encode(serialize_outpoint(op)); }
std::string key_validator(const PubKey32& pub) { return "V:" + hex_encode(Bytes(pub.begin(), pub.end())); }

#ifdef SC_HAS_ROCKSDB
class DB::RocksImpl {
 public:
  std::unique_ptr<rocksdb::DB> db;
};
#endif

bool DB::open(const std::string& path) {
  path_ = path;
#ifdef SC_HAS_ROCKSDB
  rocks_ = std::make_unique<RocksImpl>();
  rocksdb::Options options;
  options.create_if_missing = true;
  rocksdb::DB* raw = nullptr;
  auto s = rocksdb::DB::Open(options, path, &raw);
  if (!s.ok()) return false;
  rocks_->db.reset(raw);
  return true;
#else
  std::filesystem::create_directories(path_);
  return load_file();
#endif
}

bool DB::put(const std::string& key, const Bytes& value) {
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
