cmake_minimum_required(VERSION 3.20)
project(selfcoin_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

# Optional libs: RocksDB and libsodium. Build falls back gracefully if unavailable.
find_library(SODIUM_LIB sodium)
find_path(SODIUM_INCLUDE_DIR sodium.h)
if(SODIUM_LIB AND SODIUM_INCLUDE_DIR)
  message(STATUS "Using libsodium")
  add_compile_definitions(SC_HAS_LIBSODIUM=1)
endif()

find_library(ROCKSDB_LIB rocksdb)
find_path(ROCKSDB_INCLUDE_DIR rocksdb/db.h)
if(ROCKSDB_LIB AND ROCKSDB_INCLUDE_DIR)
  message(STATUS "Using RocksDB")
  add_compile_definitions(SC_HAS_ROCKSDB=1)
endif()

add_library(selfcoin_core
  src/common/types.cpp
  src/codec/bytes.cpp
  src/codec/varint.cpp
  src/crypto/hash.cpp
  src/crypto/ed25519.cpp
  src/merkle/merkle.cpp
  src/address/address.cpp
  src/utxo/tx.cpp
  src/utxo/validate.cpp
  src/utxo/signing.cpp
  src/mempool/mempool.cpp
  src/consensus/validators.cpp
  src/consensus/votes.cpp
  src/storage/db.cpp
  src/p2p/framing.cpp
  src/p2p/messages.cpp
  src/p2p/peer_manager.cpp
  src/node/node.cpp
)

target_include_directories(selfcoin_core PUBLIC src)
target_link_libraries(selfcoin_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
if(SODIUM_LIB AND SODIUM_INCLUDE_DIR)
  target_include_directories(selfcoin_core PUBLIC ${SODIUM_INCLUDE_DIR})
  target_link_libraries(selfcoin_core PUBLIC ${SODIUM_LIB})
endif()
if(ROCKSDB_LIB AND ROCKSDB_INCLUDE_DIR)
  target_include_directories(selfcoin_core PUBLIC ${ROCKSDB_INCLUDE_DIR})
  target_link_libraries(selfcoin_core PUBLIC ${ROCKSDB_LIB})
endif()

target_compile_options(selfcoin_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(selfcoin-node apps/selfcoin-node/main.cpp)
target_link_libraries(selfcoin-node PRIVATE selfcoin_core)

add_executable(selfcoin-cli apps/selfcoin-cli/main.cpp)
target_link_libraries(selfcoin-cli PRIVATE selfcoin_core)

add_executable(selfcoin-tests
  tests/test_main.cpp
  tests/test_codec.cpp
  tests/test_crypto.cpp
  tests/test_address.cpp
  tests/test_consensus.cpp
  tests/test_mempool.cpp
  tests/test_integration.cpp
)
target_link_libraries(selfcoin-tests PRIVATE selfcoin_core)

enable_testing()
add_test(NAME selfcoin-tests COMMAND selfcoin-tests)
