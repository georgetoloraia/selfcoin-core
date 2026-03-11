# Bootstrap And Sync Debugging

This document is for debugging the highest-risk runtime path in `selfcoin-core`:

- bootstrap-template chain formation
- follower bootstrap-validator adoption
- finalized-tip/block sync
- sponsored bootstrap validator join

The goal is operational debugging, not protocol marketing.

## 1. Mental model

In bootstrap-template mode:
- a custom genesis has no initial validators
- the first node can bind itself as the bootstrap validator
- later nodes are supposed to connect, adopt that bootstrap validator, sync finalized blocks, and only later become validators

Main file:
- [src/node/node.cpp](./../src/node/node.cpp)

Important functions:
- `maybe_self_bootstrap_template()`
- `bootstrap_template_bind_validator()`
- `maybe_adopt_bootstrap_validator_from_peer(...)`
- `request_finalized_tip(...)`
- `maybe_request_sync_parent_locked(...)`
- `maybe_apply_buffered_sync_blocks_locked()`
- `build_bootstrap_validator_join_tx(...)`
- `maybe_submit_bootstrap_join()`

## 2. Happy-path sequence

1. first node starts with custom genesis and no configured bootstrap peers
2. first node self-bootstraps as sole validator
3. follower connects to bootstrap peer
4. follower completes `VERSION` / `VERACK`
5. follower learns bootstrap validator identity
6. follower requests finalized tip
7. follower requests missing blocks
8. follower applies finalized state
9. bootstrap node may later sponsor the follower as a validator

## 3. Relevant P2P messages

Files:
- [src/p2p/messages.hpp](./../src/p2p/messages.hpp)
- [src/p2p/messages.cpp](./../src/p2p/messages.cpp)

Messages that matter most here:
- `VERSION`
- `VERACK`
- `GET_FINALIZED_TIP`
- `FINALIZED_TIP`
- `GET_BLOCK`
- `BLOCK`
- `GETADDR`
- `ADDR`

## 4. Main failure modes

### A. Follower never self-bootstraps, but also never joins

Symptoms:
- `height=0`
- `validators_total=0` or `1`
- `MiningLOG not found`
- repeated `round-timeout`

Likely control-flow area:
- `request_finalized_tip(...)`
- `handle_message(... FINALIZED_TIP ...)`
- `maybe_request_sync_parent_locked(...)`
- `maybe_apply_buffered_sync_blocks_locked()`

### B. Follower connects but never adopts bootstrap validator

Symptoms:
- established connection exists
- follower remains with no usable validator state
- block 1 cannot be validated/applied

Likely control-flow area:
- `handle_message(... VERSION ...)`
- `handle_message(... FINALIZED_TIP ...)`
- `maybe_adopt_bootstrap_validator_from_peer(...)`

### C. Follower adopts validator identity but still stays at height 0

Symptoms:
- `validators_total` becomes nonzero
- `height` remains 0
- no local mining

Likely control-flow area:
- `GET_BLOCK` / `BLOCK`
- parent buffering
- finalized block application

### D. Validator set expands too early and liveness drops

Symptoms:
- bootstrap node enters `WAITING_FOR_QUORUM`
- second validator is active in registry
- new node is not actually voting

Likely control-flow area:
- `maybe_submit_bootstrap_join()`
- validator warmup / activation in `ValidatorRegistry::advance_height(...)`

## 5. Best log insertion points

### In [src/node/node.cpp](./../src/node/node.cpp)

- `handle_message(...)`
  - log every `VERSION`, `VERACK`, `FINALIZED_TIP`, `GET_BLOCK`, `BLOCK`, `PROPOSE`, `VOTE`

- `maybe_adopt_bootstrap_validator_from_peer(...)`
  - log why adoption succeeds or why it does not

- `request_finalized_tip(...)`
  - log who was asked and why

- `maybe_request_sync_parent_locked(...)`
  - log missing parent hash requests

- `maybe_apply_buffered_sync_blocks_locked()`
  - log buffered height/hash replay attempts

- `finalize_if_quorum(...)`
  - log committee size, quorum threshold, valid signature count

- `build_bootstrap_validator_join_tx(...)`
  - log when sponsored join tx creation is attempted

- `maybe_submit_bootstrap_join()`
  - log why a joiner is or is not considered ready

### In [src/p2p/peer_manager.cpp](./../src/p2p/peer_manager.cpp)

- inbound accept
- outbound dial success/failure
- handshake timeout
- idle timeout
- promotion to established
- peer removal/drop reasons

## 6. Important counters to watch

Runtime summaries emitted from [src/node/node.cpp](./../src/node/node.cpp) currently expose several useful counters.

Watch:
- `height`
- `tip`
- `peers`
- `inbound`
- `established`
- `addrman`
- `state`
- `bootstrap`
- `source`
- `pending_joiners`

Interpretation:
- `height=0` with `established>0` often means post-handshake sync is failing
- `validators_total=0` or mismatch with peer state often means bootstrap validator adoption failed
- `WAITING_FOR_QUORUM` after validator growth often means activation outran readiness

## 7. Tests worth reading while debugging

File:
- [tests/test_integration.cpp](./../tests/test_integration.cpp)

Most relevant:
- `test_single_node_custom_genesis_bootstraps_and_finalizes`
- `test_second_fresh_node_adopts_bootstrap_validator_and_syncs`
- `test_second_node_auto_joins_as_validator_on_chain`
- `test_bootstrap_joiner_is_not_sponsored_until_synced`
- `test_late_joiner_requests_finalized_tip_and_catches_up`

These are the best “intended behavior” references for bootstrap-template mode.

## 8. Practical debug order

1. confirm bootstrap node is actually advancing
   - `finalized height=...`
   - `MiningLOG`

2. confirm follower has correct seed and genesis
   - `SEEDS.json`
   - genesis hash/fingerprint

3. confirm handshake completes
   - `VERSION`
   - `VERACK`
   - `PeerInfo::established()`

4. confirm follower adopts bootstrap validator
   - `maybe_adopt_bootstrap_validator_from_peer(...)`

5. confirm `FINALIZED_TIP` exchange happens
   - `request_finalized_tip(...)`
   - `send_finalized_tip(...)`

6. confirm block sync begins
   - `GET_BLOCK`
   - `BLOCK`

7. confirm missing-parent replay path
   - `maybe_request_sync_parent_locked(...)`
   - `maybe_apply_buffered_sync_blocks_locked()`

8. confirm finalized application
   - `persist_finalized_block(...)`
   - `apply_validator_state_changes(...)`
   - `apply_block_to_utxo(...)`

9. only then debug validator sponsorship and activation
   - `maybe_submit_bootstrap_join()`

## 9. Open questions to recheck directly in code

Current answers from the code path in [src/node/node.cpp](./../src/node/node.cpp):

- every peer that reaches `VERACK` is sent `FINALIZED_TIP` and is also asked for `GET_FINALIZED_TIP`
- bootstrap validator adoption can happen from `VERSION` metadata, with a fallback retry on later `FINALIZED_TIP`
- sponsored join still waits for a peer claiming the joiner pubkey to be established and at the same finalized tip as the sponsor, which avoids sponsoring a clearly-unsynced joiner
- plain-text runtime summary now treats `peers` as total live peers and reports outbound separately as `outbound=x/target`, so the counters line up with the debugging checklist

Useful new runtime logs now exist at the critical decision points:

- peer connect/disconnect and timeout reasons
- bootstrap validator adoption success and skip reasons
- `VERSION`, `VERACK`, `GET_FINALIZED_TIP`, `FINALIZED_TIP`, `GET_BLOCK`, `BLOCK`, `PROPOSE`, `VOTE`
- finalized-tip requests/sends
- sync-parent requests and buffered-sync replay/apply outcomes

## 10. Debugging summary

The pipeline to keep in your head is:

`connect -> handshake -> establish -> adopt bootstrap validator -> request finalized tip -> request blocks -> request missing parents -> replay buffered blocks -> apply finalized state -> optionally sponsor validator join`

If a follower stays at height 0, the bug is almost always somewhere in that exact pipeline.
