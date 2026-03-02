#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <string>
#include <algorithm>

#include "address/address.hpp"
#include "common/network.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/hash.hpp"
#include "genesis/genesis.hpp"
#include "p2p/framing.hpp"
#include "p2p/messages.hpp"
#include "storage/db.hpp"
#include "utxo/signing.hpp"

namespace {

std::optional<int> connect_tcp(const std::string& host, std::uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return std::nullopt;

  int fd = -1;
  for (addrinfo* it = res; it != nullptr; it = it->ai_next) {
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return std::nullopt;
  return fd;
}

bool do_handshake_v0(int fd) {
  selfcoin::p2p::VersionMsg v;
  v.timestamp = static_cast<std::uint64_t>(std::time(nullptr));
  v.nonce = 0xC011CAFE;
  v.start_height = 0;
  v.start_hash = selfcoin::zero_hash();

  if (!selfcoin::p2p::write_frame_fd(fd, selfcoin::p2p::Frame{selfcoin::p2p::MsgType::VERSION, selfcoin::p2p::ser_version(v)})) {
    return false;
  }

  bool got_version = false;
  bool got_verack = false;
  bool sent_verack = false;

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (std::chrono::steady_clock::now() < deadline && (!got_version || !got_verack)) {
    auto f = selfcoin::p2p::read_frame_fd(fd);
    if (!f.has_value()) return false;
    if (f->msg_type == selfcoin::p2p::MsgType::VERSION) {
      auto pv = selfcoin::p2p::de_version(f->payload);
      if (!pv.has_value()) return false;
      got_version = true;
      if (!sent_verack) {
        if (!selfcoin::p2p::write_frame_fd(fd, selfcoin::p2p::Frame{selfcoin::p2p::MsgType::VERACK, {}})) {
          return false;
        }
        sent_verack = true;
      }
    } else if (f->msg_type == selfcoin::p2p::MsgType::VERACK) {
      got_verack = true;
    }
  }

  return got_version && got_verack;
}

std::optional<std::array<std::uint8_t, 32>> decode_hex32(const std::string& hex) {
  auto b = selfcoin::hex_decode(hex);
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  std::array<std::uint8_t, 32> out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

std::optional<std::array<std::uint8_t, 64>> decode_hex64(const std::string& hex) {
  auto b = selfcoin::hex_decode(hex);
  if (!b.has_value() || b->size() != 64) return std::nullopt;
  std::array<std::uint8_t, 64> out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage:\n"
              << "  selfcoin-cli tip --db <dir>\n"
              << "  selfcoin-cli create_keypair [--seed-hex <32b-hex>] [--hrp tsc]\n"
              << "  selfcoin-cli address_from_pubkey --hrp <sc|tsc> --pubkey <hex32>\n"
              << "  selfcoin-cli build_p2pkh_tx --prev-txid <hex32> --prev-index <u32> --prev-value <u64> --from-privkey <hex32> --to-address <addr> --amount <u64> --fee <u64> [--change-address <addr>]\n"
              << "  selfcoin-cli create_validator_bond_tx --prev-txid <hex32> --prev-index <u32> --prev-value <u64> --from-privkey <hex32> [--fee <u64>] [--change-address <addr>]\n"
              << "  selfcoin-cli create_unbond_tx --bond-txid <hex32> --bond-index <u32> --bond-value <u64> --validator-pubkey <hex32> --validator-privkey <hex32> [--fee <u64>]\n"
              << "  selfcoin-cli create_slash_tx --bond-txid <hex32> --bond-index <u32> --bond-value <u64> --a-height <u64> --a-round <u32> --a-block <hex32> --a-pub <hex32> --a-sig <hex64> --b-height <u64> --b-round <u32> --b-block <hex32> --b-pub <hex32> --b-sig <hex64> [--fee <u64>]\n"
              << "  selfcoin-cli genesis_build --in <genesis.json> --out <genesis.bin>\n"
              << "  selfcoin-cli genesis_hash --in <genesis.bin>\n"
              << "  selfcoin-cli genesis_verify --json <genesis.json> --bin <genesis.bin>\n"
              << "  selfcoin-cli broadcast_tx --host <ip> --port <p> --tx-hex <hex>\n";
    return 1;
  }

  std::string cmd = argv[1];
  if (cmd == "tip") {
    std::string db_path = "./data/node";
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--db" && i + 1 < argc) db_path = argv[++i];
    }

    selfcoin::storage::DB db;
    if (!db.open(db_path)) {
      std::cerr << "failed to open db\n";
      return 1;
    }
    auto tip = db.get_tip();
    if (!tip) {
      std::cout << "no tip\n";
      return 0;
    }
    std::cout << "height=" << tip->height << " hash=" << selfcoin::hex_encode32(tip->hash) << "\n";
    return 0;
  }

  if (cmd == "genesis_build") {
    std::string in_path;
    std::string out_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--in" && i + 1 < argc) in_path = argv[++i];
      else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
    }
    if (in_path.empty() || out_path.empty()) {
      std::cerr << "genesis_build requires --in and --out\n";
      return 1;
    }
    std::string err;
    auto doc = selfcoin::genesis::load_from_path(in_path, &err);
    if (!doc) {
      std::cerr << "failed to load genesis json: " << err << "\n";
      return 1;
    }
    if (!selfcoin::genesis::validate_document(*doc, selfcoin::mainnet_network(), &err, 4)) {
      std::cerr << "genesis validation failed: " << err << "\n";
      return 1;
    }
    const auto bin = selfcoin::genesis::encode_bin(*doc);
    if (!selfcoin::genesis::write_bin_to_path(out_path, bin, &err)) {
      std::cerr << "failed to write genesis bin: " << err << "\n";
      return 1;
    }
    const auto ghash = selfcoin::genesis::hash_bin(bin);
    const auto gbid = selfcoin::genesis::block_id(*doc);
    std::cout << "network_id=" << selfcoin::hex_encode(selfcoin::Bytes(doc->network_id.begin(), doc->network_id.end())) << "\n";
    std::cout << "magic=" << doc->magic << "\n";
    std::cout << "validator_count=" << doc->initial_validators.size() << "\n";
    std::cout << "genesis_hash=" << selfcoin::hex_encode32(ghash) << "\n";
    std::cout << "genesis_block_id=" << selfcoin::hex_encode32(gbid) << "\n";
    return 0;
  }

  if (cmd == "genesis_hash") {
    std::string in_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--in" && i + 1 < argc) in_path = argv[++i];
    }
    if (in_path.empty()) {
      std::cerr << "genesis_hash requires --in\n";
      return 1;
    }
    std::string err;
    auto bin = selfcoin::genesis::load_bin_from_path(in_path, &err);
    if (!bin) {
      std::cerr << "failed to load genesis bin: " << err << "\n";
      return 1;
    }
    auto doc = selfcoin::genesis::decode_bin(*bin, &err);
    if (!doc) {
      std::cerr << "failed to decode genesis bin: " << err << "\n";
      return 1;
    }
    const auto ghash = selfcoin::genesis::hash_bin(*bin);
    const auto gbid = selfcoin::genesis::block_id(*doc);
    std::cout << "network_id=" << selfcoin::hex_encode(selfcoin::Bytes(doc->network_id.begin(), doc->network_id.end())) << "\n";
    std::cout << "magic=" << doc->magic << "\n";
    std::cout << "validator_count=" << doc->initial_validators.size() << "\n";
    std::cout << "genesis_hash=" << selfcoin::hex_encode32(ghash) << "\n";
    std::cout << "genesis_block_id=" << selfcoin::hex_encode32(gbid) << "\n";
    return 0;
  }

  if (cmd == "genesis_verify") {
    std::string json_path;
    std::string bin_path;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--json" && i + 1 < argc) json_path = argv[++i];
      else if (a == "--bin" && i + 1 < argc) bin_path = argv[++i];
    }
    if (json_path.empty() || bin_path.empty()) {
      std::cerr << "genesis_verify requires --json and --bin\n";
      return 1;
    }
    std::string err;
    auto doc = selfcoin::genesis::load_from_path(json_path, &err);
    if (!doc) {
      std::cerr << "failed to load genesis json: " << err << "\n";
      return 1;
    }
    if (!selfcoin::genesis::validate_document(*doc, selfcoin::mainnet_network(), &err, 4)) {
      std::cerr << "genesis validation failed: " << err << "\n";
      return 1;
    }
    auto existing = selfcoin::genesis::load_bin_from_path(bin_path, &err);
    if (!existing) {
      std::cerr << "failed to read genesis bin: " << err << "\n";
      return 1;
    }
    const auto rebuilt = selfcoin::genesis::encode_bin(*doc);
    if (*existing != rebuilt) {
      std::cerr << "genesis verify failed: binary mismatch\n";
      return 1;
    }
    const auto ghash = selfcoin::genesis::hash_bin(rebuilt);
    const auto gbid = selfcoin::genesis::block_id(*doc);
    std::cout << "verified=1\n";
    std::cout << "genesis_hash=" << selfcoin::hex_encode32(ghash) << "\n";
    std::cout << "genesis_block_id=" << selfcoin::hex_encode32(gbid) << "\n";
    return 0;
  }

  if (cmd == "create_keypair") {
    std::string seed_hex;
    std::string hrp = "tsc";
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--seed-hex" && i + 1 < argc) seed_hex = argv[++i];
      if (a == "--hrp" && i + 1 < argc) hrp = argv[++i];
    }

    std::array<std::uint8_t, 32> seed{};
    if (!seed_hex.empty()) {
      auto s = decode_hex32(seed_hex);
      if (!s.has_value()) {
        std::cerr << "--seed-hex must be 32 bytes hex\n";
        return 1;
      }
      seed = *s;
    } else {
      std::random_device rd;
      for (auto& b : seed) b = static_cast<std::uint8_t>(rd());
    }

    auto kp = selfcoin::crypto::keypair_from_seed32(seed);
    if (!kp.has_value()) {
      std::cerr << "failed to create keypair\n";
      return 1;
    }
    auto pkh = selfcoin::crypto::h160(selfcoin::Bytes(kp->public_key.begin(), kp->public_key.end()));
    auto addr = selfcoin::address::encode_p2pkh(hrp, pkh);

    std::cout << "privkey_hex=" << selfcoin::hex_encode(selfcoin::Bytes(seed.begin(), seed.end())) << "\n";
    std::cout << "pubkey_hex=" << selfcoin::hex_encode(selfcoin::Bytes(kp->public_key.begin(), kp->public_key.end())) << "\n";
    if (addr.has_value()) std::cout << "address=" << *addr << "\n";
    return 0;
  }

  if (cmd == "address_from_pubkey" || cmd == "addr") {
    std::string hrp = "tsc";
    std::string pub_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--hrp" && i + 1 < argc) hrp = argv[++i];
      if (a == "--pubkey" && i + 1 < argc) pub_hex = argv[++i];
    }
    if (pub_hex.empty()) {
      std::cerr << "--pubkey is required\n";
      return 1;
    }

    auto b = selfcoin::hex_decode(pub_hex);
    if (!b || b->size() != 32) {
      std::cerr << "pubkey must be 32 bytes hex\n";
      return 1;
    }
    auto pkh = selfcoin::crypto::h160(*b);
    auto addr = selfcoin::address::encode_p2pkh(hrp, pkh);
    if (!addr) {
      std::cerr << "address encoding failed\n";
      return 1;
    }
    std::cout << *addr << "\n";
    return 0;
  }

  if (cmd == "build_p2pkh_tx") {
    std::string prev_txid_hex;
    std::uint32_t prev_index = 0;
    std::uint64_t prev_value = 0;
    std::string from_priv_hex;
    std::string to_addr;
    std::string change_addr;
    std::uint64_t amount = 0;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hex = argv[++i];
      else if (a == "--prev-index" && i + 1 < argc) prev_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--prev-value" && i + 1 < argc) prev_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--from-privkey" && i + 1 < argc) from_priv_hex = argv[++i];
      else if (a == "--to-address" && i + 1 < argc) to_addr = argv[++i];
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--amount" && i + 1 < argc) amount = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto prev_txid = decode_hex32(prev_txid_hex);
    auto priv = decode_hex32(from_priv_hex);
    auto to = selfcoin::address::decode(to_addr);
    if (!prev_txid.has_value() || !priv.has_value() || !to.has_value()) {
      std::cerr << "invalid required args\n";
      return 1;
    }
    if (prev_value < amount + fee) {
      std::cerr << "insufficient prev output value\n";
      return 1;
    }

    selfcoin::OutPoint op{*prev_txid, prev_index};

    auto kp = selfcoin::crypto::keypair_from_seed32(*priv);
    if (!kp.has_value()) {
      std::cerr << "invalid private key\n";
      return 1;
    }
    auto from_pkh = selfcoin::crypto::h160(selfcoin::Bytes(kp->public_key.begin(), kp->public_key.end()));
    selfcoin::TxOut prev_out{prev_value, selfcoin::address::p2pkh_script_pubkey(from_pkh)};

    std::vector<selfcoin::TxOut> outputs;
    outputs.push_back(selfcoin::TxOut{amount, selfcoin::address::p2pkh_script_pubkey(to->pubkey_hash)});

    const std::uint64_t change = prev_value - amount - fee;
    if (change > 0) {
      if (!change_addr.empty()) {
        auto ch = selfcoin::address::decode(change_addr);
        if (!ch.has_value()) {
          std::cerr << "invalid --change-address\n";
          return 1;
        }
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(ch->pubkey_hash)});
      } else {
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(from_pkh)});
      }
    }

    std::string err;
    auto tx = selfcoin::build_signed_p2pkh_tx_single_input(op, prev_out, selfcoin::Bytes(priv->begin(), priv->end()), outputs, &err);
    if (!tx.has_value()) {
      std::cerr << "build tx failed: " << err << "\n";
      return 1;
    }

    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_validator_bond_tx") {
    std::string prev_txid_hex;
    std::uint32_t prev_index = 0;
    std::uint64_t prev_value = 0;
    std::string from_priv_hex;
    std::string change_addr;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--prev-txid" && i + 1 < argc) prev_txid_hex = argv[++i];
      else if (a == "--prev-index" && i + 1 < argc) prev_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--prev-value" && i + 1 < argc) prev_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--from-privkey" && i + 1 < argc) from_priv_hex = argv[++i];
      else if (a == "--change-address" && i + 1 < argc) change_addr = argv[++i];
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto prev_txid = decode_hex32(prev_txid_hex);
    auto priv = decode_hex32(from_priv_hex);
    if (!prev_txid || !priv) {
      std::cerr << "invalid required args\n";
      return 1;
    }
    if (prev_value < selfcoin::BOND_AMOUNT + fee) {
      std::cerr << "insufficient prev value for bond + fee\n";
      return 1;
    }

    auto kp = selfcoin::crypto::keypair_from_seed32(*priv);
    if (!kp) {
      std::cerr << "invalid private key\n";
      return 1;
    }
    auto from_pkh = selfcoin::crypto::h160(selfcoin::Bytes(kp->public_key.begin(), kp->public_key.end()));
    selfcoin::OutPoint op{*prev_txid, prev_index};
    selfcoin::TxOut prev_out{prev_value, selfcoin::address::p2pkh_script_pubkey(from_pkh)};

    selfcoin::Bytes reg_spk{'S', 'C', 'V', 'A', 'L', 'R', 'E', 'G'};
    reg_spk.insert(reg_spk.end(), kp->public_key.begin(), kp->public_key.end());
    std::vector<selfcoin::TxOut> outputs{selfcoin::TxOut{selfcoin::BOND_AMOUNT, reg_spk}};

    const std::uint64_t change = prev_value - selfcoin::BOND_AMOUNT - fee;
    if (change > 0) {
      if (!change_addr.empty()) {
        auto ch = selfcoin::address::decode(change_addr);
        if (!ch) {
          std::cerr << "invalid change address\n";
          return 1;
        }
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(ch->pubkey_hash)});
      } else {
        outputs.push_back(selfcoin::TxOut{change, selfcoin::address::p2pkh_script_pubkey(from_pkh)});
      }
    }

    std::string err;
    auto tx = selfcoin::build_signed_p2pkh_tx_single_input(op, prev_out, selfcoin::Bytes(priv->begin(), priv->end()), outputs, &err);
    if (!tx) {
      std::cerr << "create bond tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_unbond_tx") {
    std::string bond_txid_hex;
    std::uint32_t bond_index = 0;
    std::uint64_t bond_value = selfcoin::BOND_AMOUNT;
    std::string validator_pub_hex;
    std::string validator_priv_hex;
    std::uint64_t fee = 0;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--bond-txid" && i + 1 < argc) bond_txid_hex = argv[++i];
      else if (a == "--bond-index" && i + 1 < argc) bond_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (a == "--bond-value" && i + 1 < argc) bond_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (a == "--validator-pubkey" && i + 1 < argc) validator_pub_hex = argv[++i];
      else if (a == "--validator-privkey" && i + 1 < argc) validator_priv_hex = argv[++i];
      else if (a == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }
    auto bond_txid = decode_hex32(bond_txid_hex);
    auto pub = decode_hex32(validator_pub_hex);
    auto priv = decode_hex32(validator_priv_hex);
    if (!bond_txid || !pub || !priv) {
      std::cerr << "invalid args\n";
      return 1;
    }

    selfcoin::OutPoint op{*bond_txid, bond_index};
    std::string err;
    auto tx = selfcoin::build_unbond_tx(op, *pub, bond_value, fee, selfcoin::Bytes(priv->begin(), priv->end()), &err);
    if (!tx) {
      std::cerr << "create unbond tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "create_slash_tx") {
    std::string bond_txid_hex;
    std::uint32_t bond_index = 0;
    std::uint64_t bond_value = selfcoin::BOND_AMOUNT;
    selfcoin::Vote a, b;
    std::string a_block_hex, a_pub_hex, a_sig_hex, b_block_hex, b_pub_hex, b_sig_hex;
    std::uint64_t fee = 0;

    for (int i = 2; i < argc; ++i) {
      std::string k = argv[i];
      if (k == "--bond-txid" && i + 1 < argc) bond_txid_hex = argv[++i];
      else if (k == "--bond-index" && i + 1 < argc) bond_index = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (k == "--bond-value" && i + 1 < argc) bond_value = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (k == "--a-height" && i + 1 < argc) a.height = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (k == "--a-round" && i + 1 < argc) a.round = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (k == "--a-block" && i + 1 < argc) a_block_hex = argv[++i];
      else if (k == "--a-pub" && i + 1 < argc) a_pub_hex = argv[++i];
      else if (k == "--a-sig" && i + 1 < argc) a_sig_hex = argv[++i];
      else if (k == "--b-height" && i + 1 < argc) b.height = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      else if (k == "--b-round" && i + 1 < argc) b.round = static_cast<std::uint32_t>(std::stoul(argv[++i]));
      else if (k == "--b-block" && i + 1 < argc) b_block_hex = argv[++i];
      else if (k == "--b-pub" && i + 1 < argc) b_pub_hex = argv[++i];
      else if (k == "--b-sig" && i + 1 < argc) b_sig_hex = argv[++i];
      else if (k == "--fee" && i + 1 < argc) fee = static_cast<std::uint64_t>(std::stoull(argv[++i]));
    }

    auto bond_txid = decode_hex32(bond_txid_hex);
    auto a_block = decode_hex32(a_block_hex);
    auto a_pub = decode_hex32(a_pub_hex);
    auto a_sig = decode_hex64(a_sig_hex);
    auto b_block = decode_hex32(b_block_hex);
    auto b_pub = decode_hex32(b_pub_hex);
    auto b_sig = decode_hex64(b_sig_hex);
    if (!bond_txid || !a_block || !a_pub || !a_sig || !b_block || !b_pub || !b_sig) {
      std::cerr << "invalid slash args\n";
      return 1;
    }
    a.block_id = *a_block;
    a.validator_pubkey = *a_pub;
    a.signature = *a_sig;
    b.block_id = *b_block;
    b.validator_pubkey = *b_pub;
    b.signature = *b_sig;

    selfcoin::OutPoint op{*bond_txid, bond_index};
    std::string err;
    auto tx = selfcoin::build_slash_tx(op, bond_value, a, b, fee, &err);
    if (!tx) {
      std::cerr << "create slash tx failed: " << err << "\n";
      return 1;
    }
    std::cout << "txid=" << selfcoin::hex_encode32(tx->txid()) << "\n";
    std::cout << "tx_hex=" << selfcoin::hex_encode(tx->serialize()) << "\n";
    return 0;
  }

  if (cmd == "broadcast_tx") {
    std::string host = "127.0.0.1";
    std::uint16_t port = 18444;
    std::string tx_hex;
    for (int i = 2; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--host" && i + 1 < argc) host = argv[++i];
      else if (a == "--port" && i + 1 < argc) port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
      else if (a == "--tx-hex" && i + 1 < argc) tx_hex = argv[++i];
    }
    if (tx_hex.empty()) {
      std::cerr << "--tx-hex is required\n";
      return 1;
    }

    auto raw = selfcoin::hex_decode(tx_hex);
    if (!raw.has_value() || !selfcoin::Tx::parse(*raw).has_value()) {
      std::cerr << "invalid tx hex\n";
      return 1;
    }

    auto fd_opt = connect_tcp(host, port);
    if (!fd_opt.has_value()) {
      std::cerr << "connect failed\n";
      return 1;
    }
    const int fd = *fd_opt;

    bool ok = do_handshake_v0(fd);
    if (!ok) {
      ::close(fd);
      std::cerr << "handshake failed\n";
      return 1;
    }

    ok = selfcoin::p2p::write_frame_fd(fd, selfcoin::p2p::Frame{selfcoin::p2p::MsgType::TX, selfcoin::p2p::ser_tx(selfcoin::p2p::TxMsg{*raw})});
    ::close(fd);
    if (!ok) {
      std::cerr << "send tx failed\n";
      return 1;
    }
    std::cout << "broadcasted tx\n";
    return 0;
  }

  std::cerr << "unknown command\n";
  return 1;
}
