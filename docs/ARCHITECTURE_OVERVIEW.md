# selfcoin-core Architecture Overview

This document explains the active `selfcoin-core` runtime as it exists in the repository today.

The goal is not to give a generic blockchain explanation. The goal is to help a contributor or reviewer understand how this codebase actually works, from process start to finalized block.

Evidence boundaries used in this document:

- `Confirmed from code`: I verified this directly in the named files/functions.
- `Inferred from control flow`: the behavior appears to follow from the current call graph and state flow, but the exact branch should be rechecked if the code moves.
- `Needs verification`: I think this is controlled by the named file/function, but it should be rechecked directly on the current branch before treating it as settled.

## What selfcoin-core is

`selfcoin-core` is a full cryptocurrency node and toolkit.

Confirmed from code:
- the main node executable is [apps/selfcoin-node/main.cpp](./../apps/selfcoin-node/main.cpp)
- the operational CLI is [apps/selfcoin-cli/main.cpp](./../apps/selfcoin-cli/main.cpp)
- the read-only HTTP/RPC lightserver is [apps/selfcoin-lightserver/main.cpp](./../apps/selfcoin-lightserver/main.cpp)
- the central runtime orchestrator is `selfcoin::node::Node` in [src/node/node.hpp](./../src/node/node.hpp) and [src/node/node.cpp](./../src/node/node.cpp)

The active runtime is a deterministic committee-finality design:

Confirmed from code:
- proposer selection is deterministic via `consensus::select_leader(...)` in [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
- committee selection is deterministic via `consensus::select_committee(...)` in [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
- quorum is computed by `consensus::quorum_threshold(...)` in [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
- vote handling and finalization are orchestrated in [src/node/node.cpp](./../src/node/node.cpp), especially `Node::handle_vote(...)` and `Node::finalize_if_quorum(...)`

This is not Bitcoin-style longest-chain consensus.

Confirmed from code:
- the runtime advances a stored finalized tip in RocksDB
- sync is driven by `FINALIZED_TIP`, `GET_BLOCK`, and `BLOCK`
- the active persistence path I traced is for finalized blocks and finalized state, not speculative fork management

This is also not a typical stake-weighted PoS chain in the active runtime.

Confirmed from code:
- the active committee/quorum path is driven by validator membership and deterministic committee selection
- I do not see an active stake-weighted proposer/committee path in the current runtime files traced here

## Main architecture

### 1. Node runtime

Files:
- [src/node/node.hpp](./../src/node/node.hpp)
- [src/node/node.cpp](./../src/node/node.cpp)

Confirmed from code:
- `Node` owns the DB, validator registry, mempool, vote tracker, peer manager, sync state, and runtime loop
- `Node::init()` opens/loads local state
- `Node::start()` starts networking and the event loop
- `Node::event_loop()` drives bootstrap, proposer timing, round progression, and status logging

### 2. P2P transport and messages

Files:
- [src/p2p/peer_manager.hpp](./../src/p2p/peer_manager.hpp)
- [src/p2p/peer_manager.cpp](./../src/p2p/peer_manager.cpp)
- [src/p2p/messages.hpp](./../src/p2p/messages.hpp)
- [src/p2p/messages.cpp](./../src/p2p/messages.cpp)
- [src/p2p/framing.hpp](./../src/p2p/framing.hpp)
- [src/p2p/framing.cpp](./../src/p2p/framing.cpp)

Confirmed from code:
- `PeerManager` owns peer sockets and per-peer handshake state
- `messages.*` defines and serializes protocol messages
- `framing.*` handles transport framing

### 3. Consensus and validator registry

Files:
- [src/consensus/validators.hpp](./../src/consensus/validators.hpp)
- [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
- [src/consensus/votes.hpp](./../src/consensus/votes.hpp)
- [src/consensus/votes.cpp](./../src/consensus/votes.cpp)

Confirmed from code:
- `ValidatorRegistry` tracks validator lifecycle and active-set selection inputs
- `VoteTracker` stores votes, detects duplicates, and surfaces equivocation evidence

### 4. UTXO validation and mempool

Files:
- [src/utxo/tx.hpp](./../src/utxo/tx.hpp)
- [src/utxo/validate.hpp](./../src/utxo/validate.hpp)
- [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
- [src/mempool/mempool.hpp](./../src/mempool/mempool.hpp)
- [src/mempool/mempool.cpp](./../src/mempool/mempool.cpp)

Confirmed from code:
- `validate_tx(...)` and `validate_block_txs(...)` live in `validate.cpp`
- mempool admission and block candidate selection live in `mempool.cpp`

### 5. Storage and finalized-state read APIs

Files:
- [src/storage/db.hpp](./../src/storage/db.hpp)
- [src/storage/db.cpp](./../src/storage/db.cpp)
- [src/lightserver/server.hpp](./../src/lightserver/server.hpp)
- [src/lightserver/server.cpp](./../src/lightserver/server.cpp)

Confirmed from code:
- RocksDB persistence is wrapped by `storage::DB`
- lightserver reads from finalized node/storage state and serves RPC methods over HTTP

There is no separate `src/state` module.

Confirmed from repo structure:
- state logic is split across `src/node`, `src/utxo`, `src/consensus`, and `src/storage`

## Important source files

- [apps/selfcoin-node/main.cpp](./../apps/selfcoin-node/main.cpp)
  - process entrypoint for the full node

- [src/node/node.cpp](./../src/node/node.cpp)
  - main orchestration file
  - startup, bootstrap, sync, proposal handling, vote handling, finalization, state application

- [src/p2p/peer_manager.cpp](./../src/p2p/peer_manager.cpp)
  - peer sockets, connect/accept loops, handshake state, transport events

- [src/p2p/messages.cpp](./../src/p2p/messages.cpp)
  - message serializers/parsers including `VERSION`, `VERACK`, `FINALIZED_TIP`, `GET_BLOCK`, `BLOCK`, `PROPOSE`, `VOTE`, `TX`

- [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
  - deterministic leader selection
  - deterministic committee selection
  - quorum formula
  - validator lifecycle and active-set logic

- [src/consensus/votes.cpp](./../src/consensus/votes.cpp)
  - vote insertion
  - duplicate detection
  - equivocation evidence

- [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
  - tx validation
  - block tx validation
  - UTXO application
  - validator-related script rules

- [src/storage/db.cpp](./../src/storage/db.cpp)
  - RocksDB keyspaces and read/write helpers

- [src/lightserver/server.cpp](./../src/lightserver/server.cpp)
  - finalized-state RPC implementation

- [tests/test_integration.cpp](./../tests/test_integration.cpp)
  - best place to read intended end-to-end behavior

## Startup sequence

### 1. Process entry

Plain English:
- `main()` parses args, builds a `Node`, initializes it, starts it, and later stops it.

Code:
- [apps/selfcoin-node/main.cpp](./../apps/selfcoin-node/main.cpp)
- `main()`
- `parse_args(...)`

Mini flow:
- `main() -> parse_args(...) -> Node node(...) -> node.init() -> node.start()`

### 2. `Node::init()`

Plain English:
- this is the true startup sequence
- it opens the keystore, DB, genesis, finalized chain state, and peer persistence

Code:
- [src/node/node.cpp](./../src/node/node.cpp)
- `Node::init()`

Confirmed from code, in order:
1. normalize DB path
2. create or load validator keystore
3. load `local_key_`
4. open RocksDB with `db_.open(...)`
5. call `init_mainnet_genesis()`
6. derive `chain_id_`
7. call `load_state()`
8. load peer persistence
9. install `PeerManager` callbacks

### 3. Genesis initialization

Plain English:
- if the DB is new, the node initializes chain identity and genesis markers
- if the DB already exists, it verifies the stored genesis matches the configured chain

Code:
- [src/node/node.cpp](./../src/node/node.cpp)
- `Node::init_mainnet_genesis()`
- [src/genesis/genesis.cpp](./../src/genesis/genesis.cpp)
- `genesis::validate_document(...)`
- `genesis::hash_doc(...)`
- `genesis::block_id(...)`

Confirmed from code:
- new DB writes genesis markers:
  - `G:`
  - `GB:`
  - `G:J`
- tip is initialized to height 0 / genesis block id
- initial validators are inserted if present

### 4. Bootstrap-template mode

Plain English:
- a custom genesis with no validators activates special chain-formation logic

Code:
- [src/node/node.cpp](./../src/node/node.cpp)
- inside `init_mainnet_genesis()`

Confirmed from code:
- `bootstrap_template_mode_ = (!use_embedded && doc->initial_validators.empty())`

### 5. State restore

Plain English:
- the node reloads finalized chain state into memory

Code:
- [src/node/node.cpp](./../src/node/node.cpp)
- `Node::load_state()`

Confirmed from code:
- loads tip
- loads UTXOs
- loads validators
- may reconstruct validator state by replay if needed

### 6. Start runtime

Plain English:
- `Node::start()` starts networking and the event loop

Code:
- [src/node/node.cpp](./../src/node/node.cpp)
- `Node::start()`
- `Node::event_loop()`

Mini flow:
- `Node::start() -> PeerManager start -> event_loop()`

## P2P handshake sequence

### Active message inventory

Confirmed from code:
- [src/p2p/messages.hpp](./../src/p2p/messages.hpp)

Active messages:
- `VERSION`
- `VERACK`
- `GETADDR`
- `ADDR`
- `GET_FINALIZED_TIP`
- `FINALIZED_TIP`
- `GET_BLOCK`
- `BLOCK`
- `PROPOSE`
- `VOTE`
- `TX`

### Handshake steps

1. socket accepted or outbound dial completes
   - [src/p2p/peer_manager.cpp](./../src/p2p/peer_manager.cpp)
   - `PeerManager::accept_loop()`
   - `PeerManager::connect_peer(...)`

2. `CONNECTED` event is sent to `Node`
   - [src/node/node.cpp](./../src/node/node.cpp)
   - peer event handling

3. node sends `VERSION`
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `send_version(peer_id)`

4. remote `VERSION` is parsed and validated
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `handle_message(...)`, `MsgType::VERSION`
   - checks:
     - protocol version
     - network id
     - genesis fingerprint

5. node may send `VERACK`
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `maybe_send_verack(peer_id)`

6. remote `VERACK` is received
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `handle_message(...)`, `MsgType::VERACK`

7. peer becomes established only when all handshake directions complete
   - [src/p2p/peer_manager.hpp](./../src/p2p/peer_manager.hpp)
   - `PeerInfo::established()`

Confirmed from code:
- `established()` requires:
  - `version_rx`
  - `verack_rx`
  - `version_tx`
  - `verack_tx`

### What handshake completion triggers

Confirmed from current code path in `Node::handle_message(...)`:
- `maybe_request_getaddr(peer_id)`
- `send_finalized_tip(peer_id)`
- `request_finalized_tip(peer_id)`

Needs verification on future branches:
- recheck the `VERACK` branch directly if message sequencing changes later

## Sync sequence for a fresh node

### Plain-English flow

1. follower connects to a peer
2. follower finishes `VERSION` / `VERACK`
3. peer tips are exchanged with `FINALIZED_TIP`
4. follower may adopt the bootstrap validator identity
5. follower requests missing blocks with `GET_BLOCK`
6. if a block arrives too far ahead, it is buffered
7. missing parents are requested
8. once block `n+1` exists, buffered descendants are replayed
9. finalized state is applied in order

### Exact code path

1. request remote tip
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `request_finalized_tip(peer_id)`

2. remote responds with its tip
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `send_finalized_tip(peer_id)`

3. store peer finalized tip metadata
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `handle_message(...)`, `MsgType::FINALIZED_TIP`
   - state:
     - `peer_finalized_tips_`

4. possibly adopt bootstrap validator from peer
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `maybe_adopt_bootstrap_validator_from_peer(...)`

5. request block by hash
   - same `FINALIZED_TIP` handling path
   - sends `GET_BLOCK`

6. receive block
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `handle_message(...)`, `MsgType::BLOCK`

7. if parent missing or block is ahead:
   - store in `buffered_sync_blocks_`
   - call `maybe_request_sync_parent_locked(...)`

8. when the next needed parent exists:
   - call `maybe_apply_buffered_sync_blocks_locked()`

9. finalized block persistence and state application:
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `persist_finalized_block(...)`
   - `apply_validator_state_changes(...)`
   - [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
   - `apply_block_to_utxo(...)`

## Consensus sequence for block finalization

### Inputs that must match on all honest nodes

Confirmed from code structure:
- previous finalized hash
- target height
- round
- active validator set
- committee sizing config
- quorum formula
- validator status/warmup rules
- tx/block validation rules
- network id / protocol version / genesis fingerprint

### Step-by-step

1. get active validators
   - [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
   - `active_sorted(...)`

2. select leader
   - [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
   - `select_leader(...)`

3. select committee
   - [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
   - `select_committee(...)`

4. compute quorum
   - [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
   - `quorum_threshold(...)`

5. proposer loop checks whether local node is leader
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `event_loop()`

6. leader builds proposal block
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `build_proposal_block(...)`

7. proposal is broadcast as `PROPOSE`
   - [src/p2p/messages.hpp](./../src/p2p/messages.hpp)
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `handle_message(...)`

8. committee members validate proposal
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `handle_propose(...)`
   - [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
   - `validate_block_txs(...)`

9. committee members sign and send `VOTE`
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `handle_propose(...)`

10. votes are recorded
   - [src/consensus/votes.cpp](./../src/consensus/votes.cpp)
   - `VoteTracker::add_vote(...)`

11. duplicate/equivocation rules enforced
   - same function

12. vote verified and counted
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `handle_vote(...)`

13. finalization when quorum exists
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `finalize_if_quorum(...)`

14. finalization side effects
   - build/store finality certificate
   - persist block
   - update height/hash tip
   - apply validator changes
   - apply UTXO changes
   - remove confirmed txs from mempool

## Validator lifecycle

### On-chain lifecycle

1. registration / bond validation
   - [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
   - validator register validation path

2. registry update
   - [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
   - `ValidatorRegistry::register_bond(...)`

3. pending state
   - `ValidatorStatus::PENDING`
   - activation delayed by warmup

4. effective activation
   - [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
   - `advance_height(...)`
   - `is_active_for_height(...)`

5. exit / unbond
   - `request_unbond(...)`

6. suspend / ban
   - `ban(...)`
   - may be driven by equivocation evidence

### Bootstrap-template-specific lifecycle

1. first node binds itself as validator
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `bootstrap_template_bind_validator()`
   - `maybe_self_bootstrap_template()`

2. fresh follower adopts bootstrap validator
   - `maybe_adopt_bootstrap_validator_from_peer(...)`

3. synced joiner may be sponsored
   - `build_bootstrap_validator_join_tx(...)`
   - `maybe_submit_bootstrap_join()`

### Test anchors

- [tests/test_integration.cpp](./../tests/test_integration.cpp)
- `test_single_node_custom_genesis_bootstraps_and_finalizes`
- `test_second_fresh_node_adopts_bootstrap_validator_and_syncs`
- `test_second_node_auto_joins_as_validator_on_chain`
- `test_bootstrap_joiner_is_not_sponsored_until_synced`

## Transaction lifecycle

1. enter from RPC
   - [src/lightserver/server.cpp](./../src/lightserver/server.cpp)
   - `broadcast_tx`

2. enter from P2P
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `handle_message(...)`, `MsgType::TX`
   - `handle_tx(...)`

3. validate transaction
   - [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
   - `validate_tx(...)`

4. mempool admission
   - [src/mempool/mempool.cpp](./../src/mempool/mempool.cpp)
   - `accept_tx(...)`

5. leader selects txs for block
   - [src/mempool/mempool.cpp](./../src/mempool/mempool.cpp)
   - `select_for_block(...)`

6. tx included in proposal
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `build_proposal_block(...)`

7. block validated
   - [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
   - `validate_block_txs(...)`

8. finalized application
   - [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
   - `apply_block_to_utxo(...)`
   - [src/node/node.cpp](./../src/node/node.cpp)
   - `apply_validator_state_changes(...)`

## Database / state model

### Storage engine

Files:
- [src/storage/db.hpp](./../src/storage/db.hpp)
- [src/storage/db.cpp](./../src/storage/db.cpp)

Main boundary:
- `storage::DB`

### Main persisted key families

Confirmed from code:
- `T:` tip
- `B:` block bytes
- `H:` height -> block hash
- `FC:H:` finality certificate by height
- `FC:B:` finality certificate by block hash
- `U:` UTXO set
- `V:` validators
- `X:` tx index
- `SU:` script UTXOs
- `SH:` script history
- `G:` genesis hash
- `GB:` genesis block id
- `G:J` bootstrap/genesis metadata

### Persistence path at finalization

Plain English:
- finalized block commit is the main write boundary

Code:
- [src/node/node.cpp](./../src/node/node.cpp)
- `persist_finalized_block(...)`
- `apply_validator_state_changes(...)`
- [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
- `apply_block_to_utxo(...)`

### Finalized-state orientation

Confirmed from the traced persistence path:
- the active flow stores finalized blocks, finalized certificates, finalized UTXO state, and finalized validator state

Needs verification if you want stronger wording:
- inspect [src/storage/db.cpp](./../src/storage/db.cpp) directly for any non-finalized candidate storage not covered by this walkthrough

## Lightserver boundary

File:
- [src/lightserver/server.cpp](./../src/lightserver/server.cpp)

Confirmed from current method routing:
- `get_tip`
- `get_status`
- `get_headers`
- `get_header_range`
- `get_block`
- `get_finality_certificate`
- `get_tx`
- `get_utxos`
- `get_committee`
- `get_roots`
- `get_utxo_proof`
- `get_validator_proof`
- `broadcast_tx`

Contributor expectation:
- treat lightserver as a finalized-state read API plus tx relay surface
- do not treat it as an alternate consensus engine

## Key invariants

- all honest nodes must agree on:
  - network id
  - protocol version
  - genesis fingerprint
- deterministic leader/committee inputs must match
- a block cannot be applied before its parent finalized chain path is known
- only unique valid committee signatures count toward quorum
- validator lifecycle must be derived from finalized chain state
- finalized tip persistence and state application must happen in block order

## Fragile areas

### Bootstrap-template mode
- failure mode:
  - self-bootstrap, follower adoption, sync, and join sponsorship interfere

### Fresh-node sync
- failure mode:
  - follower remains at height 0 even though handshake succeeded

### Bootstrap validator adoption
- failure mode:
  - follower connects but never learns the validator identity needed to validate the first real block

### Join readiness vs sponsorship
- failure mode:
  - validator set expands before follower readiness, reducing liveness

### Handshake metadata path
- failure mode:
  - connection exists but metadata is absent or late, so bootstrap logic misbehaves

## Best places to add logs

- [src/node/node.cpp](./../src/node/node.cpp)
  - `handle_message(...)`
  - `maybe_adopt_bootstrap_validator_from_peer(...)`
  - `request_finalized_tip(...)`
  - `maybe_request_sync_parent_locked(...)`
  - `maybe_apply_buffered_sync_blocks_locked()`
  - `finalize_if_quorum(...)`
- [src/p2p/peer_manager.cpp](./../src/p2p/peer_manager.cpp)
  - peer establishment transitions
  - timeout/drop paths

## Open questions

- I think the current live follower issue you were debugging is now in the post-adoption sync/apply path in [src/node/node.cpp](./../src/node/node.cpp), but that should be rechecked directly on the latest branch.
- I think `pending_bootstrap_joiners_` tracks bootstrap validator-join candidates, not raw network peer promotion, but verify directly in [src/node/node.cpp](./../src/node/node.cpp).
- If you need stronger guarantees around lightserver behavior, inspect each RPC handler branch in [src/lightserver/server.cpp](./../src/lightserver/server.cpp).

## Read this repo in this order

1. [apps/selfcoin-node/main.cpp](./../apps/selfcoin-node/main.cpp)
2. [src/node/node.hpp](./../src/node/node.hpp)
3. [src/node/node.cpp](./../src/node/node.cpp)
4. [src/p2p/peer_manager.hpp](./../src/p2p/peer_manager.hpp)
5. [src/p2p/peer_manager.cpp](./../src/p2p/peer_manager.cpp)
6. [src/p2p/messages.hpp](./../src/p2p/messages.hpp)
7. [src/p2p/messages.cpp](./../src/p2p/messages.cpp)
8. [src/consensus/validators.hpp](./../src/consensus/validators.hpp)
9. [src/consensus/validators.cpp](./../src/consensus/validators.cpp)
10. [src/consensus/votes.hpp](./../src/consensus/votes.hpp)
11. [src/consensus/votes.cpp](./../src/consensus/votes.cpp)
12. [src/utxo/tx.hpp](./../src/utxo/tx.hpp)
13. [src/utxo/validate.cpp](./../src/utxo/validate.cpp)
14. [src/mempool/mempool.cpp](./../src/mempool/mempool.cpp)
15. [src/storage/db.hpp](./../src/storage/db.hpp)
16. [src/storage/db.cpp](./../src/storage/db.cpp)
17. [src/genesis/genesis.cpp](./../src/genesis/genesis.cpp)
18. [src/lightserver/server.cpp](./../src/lightserver/server.cpp)
19. [tests/test_integration.cpp](./../tests/test_integration.cpp)
20. [apps/selfcoin-cli/main.cpp](./../apps/selfcoin-cli/main.cpp)
