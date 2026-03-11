# selfcoin-core Consensus Sequence

This document is a mechanical walkthrough of the active runtime flow in `selfcoin-core`.

It is intentionally narrow:
- startup
- handshake
- sync
- proposal
- vote
- finalization
- validator join

Use this when debugging liveness or finality.

## 1. Process start

Files:
- [apps/selfcoin-node/main.cpp](./../apps/selfcoin-node/main.cpp)
- [src/node/node.cpp](./../src/node/node.cpp)

Flow:
1. `main()`
2. `parse_args(...)`
3. construct `Node`
4. `Node::init()`
5. `Node::start()`

## 2. Initialization

File:
- [src/node/node.cpp](./../src/node/node.cpp)

Functions:
- `Node::init()`
- `Node::init_mainnet_genesis()`
- `Node::load_state()`

Flow:
1. load/create validator keystore
2. open RocksDB
3. initialize or verify genesis markers
4. derive chain identity
5. load finalized tip
6. load UTXOs
7. load validators
8. install P2P callbacks

## 3. Genesis handling

Files:
- [src/node/node.cpp](./../src/node/node.cpp)
- [src/genesis/genesis.cpp](./../src/genesis/genesis.cpp)

Functions:
- `Node::init_mainnet_genesis()`
- `genesis::validate_document(...)`
- `genesis::hash_doc(...)`
- `genesis::block_id(...)`

New DB:
1. validate genesis document
2. store `G:`, `GB:`, `G:J`
3. initialize tip to height 0
4. insert initial validators if present

Existing DB:
1. read stored genesis hash
2. compare with configured genesis
3. fail if mismatch

## 4. Event loop start

File:
- [src/node/node.cpp](./../src/node/node.cpp)

Function:
- `Node::event_loop()`

Responsibilities:
- self-bootstrap if appropriate
- retry bootstrap peer dialing
- compute leader/committee
- propose block if leader
- advance rounds on timeout
- emit runtime summaries

## 5. Handshake

Files:
- [src/p2p/peer_manager.cpp](./../src/p2p/peer_manager.cpp)
- [src/p2p/messages.cpp](./../src/p2p/messages.cpp)
- [src/node/node.cpp](./../src/node/node.cpp)

Message sequence:
1. `CONNECTED`
2. `VERSION`
3. `VERACK`

Functions:
- `Node::send_version(...)`
- `Node::maybe_send_verack(...)`
- `Node::handle_message(...)`

Peer established condition:
- [src/p2p/peer_manager.hpp](./../src/p2p/peer_manager.hpp)
- `PeerInfo::established()`
- requires:
  - `version_rx`
  - `version_tx`
  - `verack_rx`
  - `verack_tx`

## 6. Fresh-node sync

Files:
- [src/node/node.cpp](./../src/node/node.cpp)

Main functions:
- `request_finalized_tip(...)`
- `send_finalized_tip(...)`
- `maybe_adopt_bootstrap_validator_from_peer(...)`
- `maybe_request_sync_parent_locked(...)`
- `maybe_apply_buffered_sync_blocks_locked()`

Message sequence:
1. `GET_FINALIZED_TIP`
2. `FINALIZED_TIP`
3. `GET_BLOCK`
4. `BLOCK`
5. optional repeated parent `GET_BLOCK`

Flow:
1. follower requests peer finalized tip
2. peer advertises finalized height/hash
3. follower stores peer tip in `peer_finalized_tips_`
4. follower may adopt bootstrap validator
5. follower requests missing block by hash
6. if block parent missing, buffer it in `buffered_sync_blocks_`
7. request parent
8. replay buffered descendants once parent exists
9. persist/apply finalized block

## 7. Proposal sequence

Files:
- [src/node/node.cpp](./../src/node/node.cpp)
- [src/consensus/validators.cpp](./../src/consensus/validators.cpp)

Functions:
- `select_leader(...)`
- `select_committee(...)`
- `build_proposal_block(...)`

Flow:
1. derive active validators
2. compute leader for `(prev_finalized_hash, height, round)`
3. compute committee for `(prev_finalized_hash, height)`
4. if local node is leader and interval elapsed, build proposal block
5. send `PROPOSE`

## 8. Vote sequence

Files:
- [src/node/node.cpp](./../src/node/node.cpp)
- [src/consensus/votes.cpp](./../src/consensus/votes.cpp)

Functions:
- `handle_propose(...)`
- `handle_vote(...)`
- `VoteTracker::add_vote(...)`

Flow:
1. committee node receives `PROPOSE`
2. validate block
3. if valid and local node is committee member, sign block hash
4. send `VOTE`
5. vote receiver validates height, round, committee membership, signature
6. add vote to `VoteTracker`
7. detect duplicates/equivocation if applicable

## 9. Finalization sequence

Files:
- [src/node/node.cpp](./../src/node/node.cpp)
- [src/consensus/validators.cpp](./../src/consensus/validators.cpp)

Functions:
- `quorum_threshold(...)`
- `finalize_if_quorum(...)`

Flow:
1. load candidate block
2. load collected signatures for `(height, round, block_id)`
3. compute committee and quorum
4. filter unique valid committee signatures
5. if quorum reached:
   - build embedded `FinalityProof`
   - build separate `FinalityCertificate`
   - persist block
   - persist certificate
   - update tip
   - apply validator changes
   - apply UTXO changes
   - remove confirmed mempool txs

## 10. Validator join sequence

Files:
- [src/node/node.cpp](./../src/node/node.cpp)
- [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
- [src/utxo/validate.cpp](./../src/utxo/validate.cpp)

Functions:
- `maybe_adopt_bootstrap_validator_from_peer(...)`
- `build_bootstrap_validator_join_tx(...)`
- `maybe_submit_bootstrap_join()`
- `ValidatorRegistry::register_bond(...)`
- `ValidatorRegistry::advance_height(...)`

Flow:
1. follower connects and advertises validator key
2. bootstrap node tracks joiner
3. once joiner is ready enough, bootstrap node may sponsor validator register tx
4. tx finalizes
5. registry entry created in `PENDING`
6. after warmup, validator becomes effectively active

## 11. Storage boundary

Files:
- [src/storage/db.cpp](./../src/storage/db.cpp)
- [src/node/node.cpp](./../src/node/node.cpp)
- [src/utxo/validate.cpp](./../src/utxo/validate.cpp)

Main write path:
1. `persist_finalized_block(...)`
2. `apply_validator_state_changes(...)`
3. `apply_block_to_utxo(...)`

Main persisted data:
- finalized tip
- blocks
- height index
- finality certificates
- validators
- UTXOs

## 12. Test anchors

File:
- [tests/test_integration.cpp](./../tests/test_integration.cpp)

Useful tests:
- `test_single_node_custom_genesis_bootstraps_and_finalizes`
- `test_second_fresh_node_adopts_bootstrap_validator_and_syncs`
- `test_second_node_auto_joins_as_validator_on_chain`
- `test_bootstrap_joiner_is_not_sponsored_until_synced`
- `test_late_joiner_requests_finalized_tip_and_catches_up`
