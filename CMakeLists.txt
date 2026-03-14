cmake_minimum_required(VERSION 3.20)
project(selfcoin_core LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
option(SELFCOIN_SANITIZE "Enable ASan/UBSan instrumentation" OFF)
option(SELFCOIN_BUILD_FUZZ "Build fuzz harness executables" ON)
option(SELFCOIN_STRICT_WARNINGS "Enable strict warning flags" OFF)

find_package(OpenSSL REQUIRED)
find_package(Qt5 COMPONENTS Widgets QUIET)

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
  src/common/network.cpp
  src/common/chain_id.cpp
  src/common/paths.cpp
  src/codec/bytes.cpp
  src/codec/varint.cpp
  src/crypto/hash.cpp
  src/crypto/ed25519.cpp
  src/crypto/vrf.cpp
  src/crypto/smt.cpp
  src/keystore/validator_keystore.cpp
  src/genesis/genesis.cpp
  src/genesis/embedded_mainnet.cpp
  src/merkle/merkle.cpp
  src/address/address.cpp
  src/privacy/mint_client.cpp
  src/privacy/mint_scripts.cpp
  src/utxo/tx.cpp
  src/utxo/validate.cpp
  src/utxo/signing.cpp
  src/policy/hashcash.cpp
  src/mempool/mempool.cpp
  src/consensus/monetary.cpp
  src/consensus/randomness.cpp
  src/consensus/state_commitment.cpp
  src/consensus/validators.cpp
  src/consensus/vrf_sortition.cpp
  src/consensus/votes.cpp
  src/storage/db.cpp
  src/storage/snapshot.cpp
  src/p2p/framing.cpp
  src/p2p/addrman.cpp
  src/p2p/hardening.cpp
  src/p2p/messages.cpp
  src/p2p/peer_manager.cpp
  src/node/node.cpp
  src/lightserver/client.cpp
  src/lightserver/server.cpp
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

if(SELFCOIN_STRICT_WARNINGS)
  target_compile_options(selfcoin_core PRIVATE -Wall -Wextra -Wpedantic)
endif()
set(SC_SAN_FLAGS "")
if(SELFCOIN_SANITIZE)
  set(SC_SAN_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_compile_options(selfcoin_core PRIVATE ${SC_SAN_FLAGS})
  target_link_options(selfcoin_core PRIVATE -fsanitize=address,undefined)
endif()

add_executable(selfcoin-node apps/selfcoin-node/main.cpp)
target_link_libraries(selfcoin-node PRIVATE selfcoin_core)
if(SELFCOIN_SANITIZE)
  target_compile_options(selfcoin-node PRIVATE ${SC_SAN_FLAGS})
  target_link_options(selfcoin-node PRIVATE -fsanitize=address,undefined)
endif()

add_executable(selfcoin-cli apps/selfcoin-cli/main.cpp)
target_link_libraries(selfcoin-cli PRIVATE selfcoin_core)
if(SELFCOIN_SANITIZE)
  target_compile_options(selfcoin-cli PRIVATE ${SC_SAN_FLAGS})
  target_link_options(selfcoin-cli PRIVATE -fsanitize=address,undefined)
endif()

add_executable(selfcoin-lightserver apps/selfcoin-lightserver/main.cpp)
target_link_libraries(selfcoin-lightserver PRIVATE selfcoin_core)
if(SELFCOIN_SANITIZE)
  target_compile_options(selfcoin-lightserver PRIVATE ${SC_SAN_FLAGS})
  target_link_options(selfcoin-lightserver PRIVATE -fsanitize=address,undefined)
endif()

if(Qt5Widgets_FOUND)
  add_executable(selfcoin-wallet
    apps/selfcoin-wallet/main.cpp
    apps/selfcoin-wallet/wallet_window.cpp
    apps/selfcoin-wallet/wallet_store.cpp
  )
  target_link_libraries(selfcoin-wallet PRIVATE selfcoin_core Qt5::Widgets)
  if(SELFCOIN_SANITIZE)
    target_compile_options(selfcoin-wallet PRIVATE ${SC_SAN_FLAGS})
    target_link_options(selfcoin-wallet PRIVATE -fsanitize=address,undefined)
  endif()

  set(SELFCOIN_WALLET_DESKTOP_DIR "${CMAKE_INSTALL_DATAROOTDIR}/applications")
  set(SELFCOIN_WALLET_DOC_DIR "${CMAKE_INSTALL_DATAROOTDIR}/doc/selfcoin-wallet")
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/packaging/linux/selfcoin-wallet.desktop.in
    ${CMAKE_CURRENT_BINARY_DIR}/selfcoin-wallet.desktop
    @ONLY
  )

  install(TARGETS selfcoin-wallet
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/selfcoin-wallet.desktop
    DESTINATION ${SELFCOIN_WALLET_DESKTOP_DIR}
  )
  install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/REFERENCE_WALLET_SPEC.md
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/SELFCOIN_CORE_CURRENT_BEHAVIOR.md
    DESTINATION ${SELFCOIN_WALLET_DOC_DIR}
  )
else()
  message(STATUS "Qt5 Widgets not found; skipping selfcoin-wallet target")
endif()

add_executable(selfcoin-tests
  apps/selfcoin-wallet/wallet_store.cpp
  tests/test_main.cpp
  tests/test_codec.cpp
  tests/test_chain_id.cpp
  tests/test_crypto.cpp
  tests/test_vrf.cpp
  tests/test_address.cpp
  tests/test_consensus.cpp
  tests/test_sortition_v2.cpp
  tests/test_p2p.cpp
  tests/test_addrman.cpp
  tests/test_monetary.cpp
  tests/test_state_commitment.cpp
  tests/test_smt.cpp
  tests/test_bonding.cpp
  tests/test_finality_certificate.cpp
  tests/test_snapshot.cpp
  tests/test_validator_v4.cpp
  tests/test_mempool.cpp
  tests/test_hardening.cpp
  tests/test_protocol_scope.cpp
  tests/test_privacy.cpp
  tests/test_genesis.cpp
  tests/test_paths.cpp
  tests/test_keystore.cpp
  tests/test_wallet_store.cpp
  tests/test_mainnet_characterization.cpp
  tests/test_integration.cpp
  tests/test_lightserver.cpp
)
target_link_libraries(selfcoin-tests PRIVATE selfcoin_core)
target_include_directories(selfcoin-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(SELFCOIN_SANITIZE)
  target_compile_options(selfcoin-tests PRIVATE ${SC_SAN_FLAGS})
  target_link_options(selfcoin-tests PRIVATE -fsanitize=address,undefined)
endif()

if(SELFCOIN_BUILD_FUZZ)
  add_executable(fuzz_p2p_frame fuzz/fuzz_p2p_frame.cpp)
  target_link_libraries(fuzz_p2p_frame PRIVATE selfcoin_core)
  if(SELFCOIN_SANITIZE)
    target_compile_options(fuzz_p2p_frame PRIVATE ${SC_SAN_FLAGS})
    target_link_options(fuzz_p2p_frame PRIVATE -fsanitize=address,undefined)
  endif()
  add_executable(fuzz_tx_parse fuzz/fuzz_tx_parse.cpp)
  target_link_libraries(fuzz_tx_parse PRIVATE selfcoin_core)
  if(SELFCOIN_SANITIZE)
    target_compile_options(fuzz_tx_parse PRIVATE ${SC_SAN_FLAGS})
    target_link_options(fuzz_tx_parse PRIVATE -fsanitize=address,undefined)
  endif()
endif()

enable_testing()
add_test(NAME selfcoin-tests COMMAND selfcoin-tests)
set_tests_properties(selfcoin-tests PROPERTIES RESOURCE_LOCK ports)

set(CPACK_PACKAGE_NAME "selfcoin-wallet")
set(CPACK_PACKAGE_VENDOR "selfcoin")
set(CPACK_PACKAGE_CONTACT "selfcoin")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "SelfCoin reference desktop wallet")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_GENERATOR "TGZ;ZIP")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}")
include(CPack)
