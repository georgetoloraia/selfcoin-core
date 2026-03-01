#include <iostream>
#include <string>

#include "address/address.hpp"
#include "crypto/hash.hpp"
#include "storage/db.hpp"

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage:\n"
              << "  selfcoin-cli tip --db <dir>\n"
              << "  selfcoin-cli addr --hrp <sc|tsc> --pubkey <hex32>\n";
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

  if (cmd == "addr") {
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

  std::cerr << "unknown command\n";
  return 1;
}
