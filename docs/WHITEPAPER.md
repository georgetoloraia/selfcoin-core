# SelfCoin Whitepaper (Repository-Grounded)

## How To Review
- Consensus: verify sections 5, 6 against [`src/node/node.cpp`](../src/node/node.cpp), [`src/consensus/validators.cpp`](../src/consensus/validators.cpp), [`src/consensus/votes.cpp`](../src/consensus/votes.cpp).
- Economics: verify section 8 against [`src/consensus/monetary.cpp`](../src/consensus/monetary.cpp) and coinbase checks in [`src/utxo/validate.cpp`](../src/utxo/validate.cpp).
- Wallet/API: verify sections 10 and 11 against [`src/lightserver/server.cpp`](../src/lightserver/server.cpp), [`spec/SELFCOIN_WALLET_API_V1.md`](../spec/SELFCOIN_WALLET_API_V1.md), and [`sdk/selfcoin-wallet-js`](../sdk/selfcoin-wallet-js).
- Mainnet/genesis: verify section 11 against [`src/genesis/genesis.cpp`](../src/genesis/genesis.cpp), [`src/common/network.cpp`](../src/common/network.cpp), and [`mainnet/*`](../mainnet).

## 1) Abstract
SelfCoin is a C++20 digital-cash protocol and node stack that prioritizes deterministic finality over probabilistic confirmation.
It uses finalized-chain-first operation: nodes only advance from the latest finalized block and do not build speculative branches.
Consensus is BFT-style with deterministic leader selection, deterministic committee selection, and quorum finality.
Validator accountability is enforced through on-chain bond registration, warmup activation, unbond delay, and slashable equivocation evidence.
The ledger model is UTXO-based, with strict P2PKH script validation and explicit handling for validator bond scripts.
Monetary policy is integer-only and deterministic by block height, with a hard cap schedule and deterministic payout splitting.
Networking is a compact framed TCP protocol with explicit network identity/version checks and hardened resource controls.
Light clients interact through a finalized-only JSON-RPC lightserver API.
A TypeScript SDK implements non-custodial wallet operations that are intended to match C++ rules byte-for-byte.
Mainnet planning includes profile isolation, deterministic genesis artifacts, and reproducibility tooling.
This document describes current repository behavior; it is a technical architecture reference, not an investment prospectus.

## 2) Motivation & Design Goals
SelfCoin targets neutral digital cash with deterministic protocol behavior and non-custodial ownership.
Design goals are: consensus determinism, validator accountability, minimal script complexity, and wallet interoperability via finalized-only APIs.
Implementation: finalized-only progression and round logic are in `Node::event_loop`, `Node::handle_propose`, and `Node::finalize_if_quorum` ([`src/node/node.cpp`](../src/node/node.cpp)).
Implementation: non-custodial model is reflected by client-side signing in SDK (`signInputP2PKH`) and server-side stateless RPC (`broadcast_tx`) ([`sdk/selfcoin-wallet-js/src/tx/tx.ts`](../sdk/selfcoin-wallet-js/src/tx/tx.ts), [`src/lightserver/server.cpp`](../src/lightserver/server.cpp)).
Implementation: no admin override path exists in consensus state transitions; validator state changes are derived from finalized blocks (`apply_validator_state_changes`) ([`src/node/node.cpp`](../src/node/node.cpp)).

## 3) System Overview
Roles:
- Full node: validates blocks/txs, runs consensus, stores finalized chain and indexes, gossips P2P messages.
  Implementation: `selfcoin-node` binary and `selfcoin::node::Node` ([`apps/selfcoin-node/main.cpp`](../apps/selfcoin-node/main.cpp), [`src/node/node.cpp`](../src/node/node.cpp)).
- Validator: an ACTIVE bonded participant eligible for committee selection and voting.
  Implementation: `ValidatorRegistry` + committee checks (`is_committee_member_for`) ([`src/consensus/validators.cpp`](../src/consensus/validators.cpp), [`src/node/node.cpp`](../src/node/node.cpp)).
- Lightserver: serves finalized-only headers/blocks/tx/utxos/committee and relays tx to node peer.
  Implementation: `selfcoin::lightserver::Server` ([`src/lightserver/server.cpp`](../src/lightserver/server.cpp)).
- Wallet: non-custodial key management, deterministic UTXO discovery/selection, tx build/sign/broadcast.
  Implementation: TS SDK `SelfCoinWallet` and `LightServerClient` ([`sdk/selfcoin-wallet-js/src/wallet/SelfCoinWallet.ts`](../sdk/selfcoin-wallet-js/src/wallet/SelfCoinWallet.ts), [`sdk/selfcoin-wallet-js/src/rpc/LightServerClient.ts`](../sdk/selfcoin-wallet-js/src/rpc/LightServerClient.ts)).

Finalized-chain-first principle:
- A proposal is accepted only for `finalized_height + 1` with matching `prev_finalized_hash`.
- Finalization persists a block and immediately resets round to `0` for next height.
Implementation: `Node::handle_propose` and `Node::finalize_if_quorum` ([`src/node/node.cpp`](../src/node/node.cpp)).

## 4) Protocol Specification Summary (Readable but exact)
### 4.1 Data structures: Tx, BlockHeader, Block, Vote, FinalityProof
- `Tx`: version, inputs, outputs, lock_time.
  Implementation: `Tx::serialize`, `Tx::parse` ([`src/utxo/tx.cpp`](../src/utxo/tx.cpp)).
- `BlockHeader`: `prev_finalized_hash`, `height`, `timestamp`, `merkle_root`, `leader_pubkey`, `round`.
  Implementation: `BlockHeader::serialize`, `BlockHeader::parse` ([`src/utxo/tx.cpp`](../src/utxo/tx.cpp)).
- `Block`: header + tx list + finality proof signatures.
  Implementation: `Block::serialize`, `Block::parse` ([`src/utxo/tx.cpp`](../src/utxo/tx.cpp)).
- `Vote`: `(height, round, block_id, validator_pubkey, signature)`.
  Implementation: vote message codec `ser_vote`, `de_vote` ([`src/p2p/messages.cpp`](../src/p2p/messages.cpp)).
- `FinalityProof`: list of `(validator_pubkey, signature)`.
  Implementation: `FinalityProof::serialize`, `FinalityProof::parse` ([`src/utxo/tx.cpp`](../src/utxo/tx.cpp)).

### 4.2 Hashing
- `txid = sha256d(Tx.serialize())`.
  Implementation: `Tx::txid` ([`src/utxo/tx.cpp`](../src/utxo/tx.cpp)).
- `block_id = sha256d("SC-BLOCK-V0" || BlockHeader.serialize())`.
  Implementation: `BlockHeader::block_id` ([`src/utxo/tx.cpp`](../src/utxo/tx.cpp)).
- Merkle leaves are `sha256d(tx_bytes)` and odd leaf duplication is used.
  Implementation: `compute_merkle_root_from_txs` ([`src/merkle/merkle.cpp`](../src/merkle/merkle.cpp)).

### 4.3 Serialization rules: little-endian, varints, strict parsing
- LE encoding for fixed integers.
  Implementation: `ByteWriter::{u16le,u32le,u64le}`, `ByteReader::{u16le,u32le,u64le}` ([`src/codec/bytes.cpp`](../src/codec/bytes.cpp)).
- ULEB128 varint with canonical/minimal requirement.
  Implementation: `decode_uleb128(..., minimal=true)` ([`src/codec/varint.cpp`](../src/codec/varint.cpp)).
- Strict full-buffer parse for protocol objects.
  Implementation: `parse_exact` and its use in tx/block/message parsers ([`src/codec/bytes.cpp`](../src/codec/bytes.cpp), [`src/utxo/tx.cpp`](../src/utxo/tx.cpp), [`src/p2p/messages.cpp`](../src/p2p/messages.cpp)).

## 5) Consensus & Finality (Core)
Deterministic leader selection:
- Leader is selected from sorted ACTIVE set using `sha256d(prev_finalized_hash || height || round)` as source.
Implementation: `select_leader` ([`src/consensus/validators.cpp`](../src/consensus/validators.cpp)).

Deterministic committee selection:
- Seed: `sha256d("SC-COMMITTEE-V0" || prev_finalized_hash || u64_le(height))`.
- Score per validator: `sha256d(seed || validator_pubkey)`.
- Ascending score order; choose first `min(max_committee, active_size)`.
Implementation: `select_committee` ([`src/consensus/validators.cpp`](../src/consensus/validators.cpp)).

Committee-only voting and quorum:
- Only committee members for `(height, round)` are accepted.
- Quorum threshold: `floor(2N/3)+1` for committee size `N`.
Implementation: `Node::handle_vote`, `quorum_threshold` ([`src/node/node.cpp`](../src/node/node.cpp), [`src/consensus/validators.cpp`](../src/consensus/validators.cpp)).

Finalization conditions:
- Candidate block exists for `(h,r)`.
- At least quorum valid distinct committee signatures over `block_id`.
- Finality proof attached and block persisted.
Implementation: `Node::finalize_if_quorum`, `persist_finalized_block` ([`src/node/node.cpp`](../src/node/node.cpp)).

Timeout/round liveness:
- If no finalization before timeout, round increments and leader recomputes.
Implementation: `Node::event_loop` with `round_timeout_ms` ([`src/node/node.cpp`](../src/node/node.cpp), [`src/common/network.hpp`](../src/common/network.hpp)).

Equivocation handling:
- Vote tracker flags conflicting votes by same validator on same `(height,round)` for different blocks.
- Node bans equivocator in validator registry if validator is committee member at that point.
Implementation: `VoteTracker::add_vote`, `Node::handle_vote` ([`src/consensus/votes.cpp`](../src/consensus/votes.cpp), [`src/node/node.cpp`](../src/node/node.cpp)).

## 6) Validator Lifecycle & Accountability
Bond registration (`SCVALREG`):
- Script shape: 8-byte prefix `SCVALREG` + 32-byte validator pubkey.
- Bond output value must equal `BOND_AMOUNT`.
Implementation: `is_validator_register_script`, `validate_tx` output checks ([`src/utxo/tx.cpp`](../src/utxo/tx.cpp), [`src/utxo/validate.cpp`](../src/utxo/validate.cpp)).

PENDING -> ACTIVE warmup:
- Registering bond sets validator to `PENDING` with `joined_height`.
- Activation after warmup blocks.
Implementation: `ValidatorRegistry::register_bond`, `ValidatorRegistry::advance_height` ([`src/consensus/validators.cpp`](../src/consensus/validators.cpp)).

Unbond flow (`SCVALUNB`):
- Bond outpoint spend can follow unbond path: one output `SCVALUNB||pubkey` and unbond-auth signature domain-separated by `SC-UNBOND-V0`.
- Spending `SCVALUNB` to normal P2PKH is blocked until `unbond_height + UNBOND_DELAY_BLOCKS`.
Implementation: `unbond_message_for_input`, unbond checks in `validate_tx` ([`src/utxo/validate.cpp`](../src/utxo/validate.cpp)).

Slashing/evidence (`SCSLASH`):
- Slash path embeds equivocation evidence as two fixed-format votes in `script_sig` with marker `SCSLASH`.
- Output must be `SCBURN||sha256d(evidence_blob)`.
- Evidence signatures and committee membership are verified.
Implementation: `parse_slash_script_sig`, slash branch in `validate_tx` ([`src/utxo/validate.cpp`](../src/utxo/validate.cpp)).

State persistence:
- Validator records (status, bond outpoint, joined/unbond heights) are persisted and reloaded from DB.
Implementation: `serialize_validator`/`parse_validator`, `put_validator`/`load_validators` ([`src/storage/db.cpp`](../src/storage/db.cpp)).

## 7) Transactions & UTXO Model
P2PKH script rules:
- `script_pubkey` must be exactly `76 A9 14 <20B> 88 AC`.
- `script_sig` must be exactly `0x40 <64B sig> 0x20 <32B pubkey>`.
Implementation: `is_p2pkh_script_pubkey`, `is_p2pkh_script_sig` ([`src/utxo/validate.cpp`](../src/utxo/validate.cpp)).

Signing domain separation:
- P2PKH message is `sha256d("SC-SIG-V0" || u32_le(input_index) || sha256d(signing_tx_bytes_with_empty_scripts))`.
Implementation: `signing_message_for_input` ([`src/utxo/validate.cpp`](../src/utxo/validate.cpp)).

Fees and validity:
- Non-coinbase tx fee = `sum(inputs) - sum(outputs)`.
- Negative fee, missing UTXOs, bad scripts/signatures, unsupported scripts are rejected.
Implementation: `validate_tx` ([`src/utxo/validate.cpp`](../src/utxo/validate.cpp)).

Mempool and block assembly:
- Accepts validated txs, rejects unconfirmed-parent dependencies and mempool double-spends.
- Selection is deterministic: highest fee first, tie-break by txid.
Implementation: `Mempool::accept_tx`, `Mempool::select_for_block` ([`src/mempool/mempool.cpp`](../src/mempool/mempool.cpp)).
- Leader assembles proposal with coinbase + mempool picks.
Implementation: `Node::build_proposal_block` ([`src/node/node.cpp`](../src/node/node.cpp)).

## 8) Monetary Policy
Implemented monetary constants:
- Total supply and emission schedule are integer-only, block-height based.
Implementation: constants and formula in `reward_units` ([`src/consensus/monetary.hpp`](../src/consensus/monetary.hpp), [`src/consensus/monetary.cpp`](../src/consensus/monetary.cpp)).

Schedule:
- `reward_units(height)` returns deterministic per-height reward until `EMISSION_BLOCKS`, then `0`.
Implementation: `reward_units` ([`src/consensus/monetary.cpp`](../src/consensus/monetary.cpp)).

Deterministic payout split:
- Let `T = reward + fees`.
- `leader = floor(T*20/100)`.
- Remaining 80% split equally among distinct signer pubkeys; remainder allocated by sorted pubkeys.
Implementation: `compute_payout` ([`src/consensus/monetary.cpp`](../src/consensus/monetary.cpp)).

Coinbase enforcement:
- Coinbase output sum must equal `reward + fees`.
- Optional strict distribution check compares outputs against deterministic payout vector.
Implementation: `validate_block_txs` ([`src/utxo/validate.cpp`](../src/utxo/validate.cpp)).

## 9) Networking
P2P framing:
- Frame fields: `magic`, `proto_version`, `msg_type`, `payload_len`, `payload`, `checksum=sha256d(payload)`.
Implementation: `encode_frame`, `decode_frame`, `read_frame_fd_timed` ([`src/p2p/framing.cpp`](../src/p2p/framing.cpp)).

Message set:
- `VERSION`, `VERACK`, `GET_FINALIZED_TIP`, `FINALIZED_TIP`, `GET_BLOCK`, `BLOCK`, `PROPOSE`, `VOTE`, `TX`.
Implementation: message codecs in [`src/p2p/messages.cpp`](../src/p2p/messages.cpp).

Handshake discipline:
- VERSION payload includes `protocol_version`, `network_id`, `feature_flags`, `node_software_version`.
- Cross-network and protocol mismatch are rejected.
- Consensus messages before VERACK/VERSION completion are rejected/scored.
Implementation: `ser_version`/`de_version`, `Node::handle_message` ([`src/p2p/messages.cpp`](../src/p2p/messages.cpp), [`src/node/node.cpp`](../src/node/node.cpp)).

Hardening:
- Timeouts: handshake/frame/idle via peer manager read loop and timed frame reads.
- Rate limiting: per-peer token buckets for TX/PROPOSE/VOTE/BLOCK and verification budgets.
- Scoring and bans: misbehavior reasons accumulate score; soft mute and temporary ban thresholds.
- Resource bounds: per-peer queue caps and bounded caches for votes/candidates/signature-verify cache.
Implementation: `PeerManager::read_loop`, `Node::check_rate_limit_locked`, `TokenBucket`, `PeerDiscipline`, `VoteVerifyCache` ([`src/p2p/peer_manager.cpp`](../src/p2p/peer_manager.cpp), [`src/node/node.cpp`](../src/node/node.cpp), [`src/p2p/hardening.cpp`](../src/p2p/hardening.cpp)).

## 10) Light Clients & Wallet Integration
Finalized-only JSON-RPC:
- Methods: `get_status`, `get_tip`, `get_headers`, `get_block`, `get_tx`, `get_utxos`, `get_committee`, `broadcast_tx`.
Implementation: `Server::handle_rpc_body` ([`src/lightserver/server.cpp`](../src/lightserver/server.cpp)); API contract in [`spec/SELFCOIN_WALLET_API_V1.md`](../spec/SELFCOIN_WALLET_API_V1.md).

Finalized-only semantics:
- Reads use finalized DB indexes and persisted chain state (`T:`, `H:`, `B:`, `X:`, script indexes).
Implementation: storage APIs in [`src/storage/db.cpp`](../src/storage/db.cpp), indexing in `Node::persist_finalized_block` ([`src/node/node.cpp`](../src/node/node.cpp)).

Scripthash definition:
- `scripthash = sha256(script_pubkey)` (single SHA-256).
Implementation: index key computation uses `crypto::sha256(out.script_pubkey)` in `persist_finalized_block`; documented in wallet API v1 spec.

Broadcast path:
- `broadcast_tx` validates tx against current finalized UTXO+validator context, then sends P2P `TX` to configured node peer.
Implementation: `Server::handle_rpc_body` (`broadcast_tx` branch), `Server::relay_tx_to_peer` ([`src/lightserver/server.cpp`](../src/lightserver/server.cpp)).

Trust model:
- Single-server mode: trust one operator.
- Multi-server mode: cross-check tips before sensitive operations.
Implementation: wallet spec section “Client Verification Modes” and SDK client quorum mode ([`spec/SELFCOIN_WALLET_API_V1.md`](../spec/SELFCOIN_WALLET_API_V1.md), [`sdk/selfcoin-wallet-js/src/rpc/LightServerClient.ts`](../sdk/selfcoin-wallet-js/src/rpc/LightServerClient.ts)).

## 11) Mainnet Bootstrapping & Genesis
Mainnet profile isolation:
- `--mainnet` selects unique `network_name`, `magic`, `network_id`, ports, limits, and default seeds.
Implementation: `mainnet_network()` and parse paths in node/lightserver arg parsers ([`src/common/network.cpp`](../src/common/network.cpp), [`src/node/node.cpp`](../src/node/node.cpp), [`src/lightserver/server.cpp`](../src/lightserver/server.cpp)).

Deterministic genesis artifacts:
- Canonical encoding: `genesis.json -> genesis.bin` with fixed field order and LE/varbytes rules.
- `genesis_hash = sha256d(genesis.bin)`.
- Deterministic `genesis_block_id` via synthetic height-0 header.
Implementation: `encode_bin`, `hash_bin`, `block_id` ([`src/genesis/genesis.cpp`](../src/genesis/genesis.cpp)); format docs in [`mainnet/GENESIS_SPEC.md`](../mainnet/GENESIS_SPEC.md).

Node initialization and DB safety:
- On empty DB, mainnet node writes genesis markers (`G:`, `GB:`), sets tip, and installs initial ACTIVE validators.
- On existing DB, mismatch of provided genesis vs stored marker aborts startup.
Implementation: `Node::init_mainnet_genesis` ([`src/node/node.cpp`](../src/node/node.cpp)).

Validator ceremony and launch docs:
- Process and deterministic selection are documented in `mainnet/GENESIS_VALIDATOR_CEREMONY.md`.
- Operational readiness guidance in `mainnet/THREAT_MODEL_AND_LAUNCH_CHECKLIST.md`.

## 12) Security Considerations
Threats addressed in-code:
- Malformed frame/payload handling with strict decode and drop paths.
- Slowloris/resource pressure mitigation via frame/handshake/idle deadlines and queue caps.
- Message spam mitigation with token buckets and peer scoring.
- Equivocation handling via vote tracker + slash evidence path.
Implementation: [`src/p2p/framing.cpp`](../src/p2p/framing.cpp), [`src/p2p/peer_manager.cpp`](../src/p2p/peer_manager.cpp), [`src/p2p/hardening.cpp`](../src/p2p/hardening.cpp), [`src/consensus/votes.cpp`](../src/consensus/votes.cpp), [`src/utxo/validate.cpp`](../src/utxo/validate.cpp).

Consensus-enforced vs policy-only:
- Consensus-enforced: tx/block validity, monetary rules, committee quorum, finality proofs, validator transitions from finalized chain.
- Policy-only: relay rate limits, peer bans, queue drop priorities, seed connectivity behavior.
Implementation references: consensus checks in `validate_block_txs` and `finalize_if_quorum`; policy checks in `check_rate_limit_locked`, `PeerDiscipline`.

Wallet guidance:
- Use non-custodial key handling and multi-lightserver tip cross-check for better integrity.
- Treat `broadcast_tx accepted=true` as relay acceptance, not finalization; wait for `get_tx` finalized presence.
Implementation: SDK `waitForFinality`, client quorum logic ([`sdk/selfcoin-wallet-js/src/wallet/SelfCoinWallet.ts`](../sdk/selfcoin-wallet-js/src/wallet/SelfCoinWallet.ts), [`sdk/selfcoin-wallet-js/src/rpc/LightServerClient.ts`](../sdk/selfcoin-wallet-js/src/rpc/LightServerClient.ts)).

## 13) Operational Considerations
Validator and node operations:
- Start node with explicit network profile and DB path; testnet/mainnet can use seed bootstrapping and peer persistence file (`peers.dat`).
Implementation: `parse_args`, `load_persisted_peers`, `persist_peers`, `try_connect_bootstrap_peers` ([`src/node/node.cpp`](../src/node/node.cpp)).

Lightserver operations:
- Lightserver can open DB read-only, and fallback to normal DB open if needed.
- Can run separately and relay tx to a node endpoint.
Implementation: `Server::init`, `relay_tx_to_peer` ([`src/lightserver/server.cpp`](../src/lightserver/server.cpp)).

Monitoring:
- Observer script polls multiple lightservers and reports lag/mismatch; exits non-zero on persistent divergence.
Implementation: [`scripts/observe.py`](../scripts/observe.py).

Upgrade policy:
- Current repo implements protocol-version and network identity checks, but no admin key upgrade path.
- Version transitions are social/operational coordination, not privileged command execution.
Implementation: handshake checks in `Node::handle_message` and profile constants in `network.cpp`.

## 14) Roadmap (Conservative, minimal-cash aligned)
What exists now in repository:
- Finalized-chain-first deterministic consensus with committee voting and quorum finality.
- Bond/unbond/slash validator lifecycle.
- UTXO ledger with strict P2PKH and deterministic monetary split.
- Hardened P2P and finalized-only lightserver APIs.
- TS non-custodial wallet SDK and mainnet genesis tooling.

Conservative next primitives (not yet implemented in current codebase):
- Additional script primitives such as multisig and timelock, if introduced without violating deterministic validation and compact encoding discipline.
- Enhanced light-client verification proofs for deeper trust minimization.
These are roadmap candidates, not claims of current functionality.

Integration examples (short):
- Any app can integrate through Wallet API v1 and the TS SDK; SelfLink is one possible integrator, but protocol design is application-neutral.

## 15) Disclaimer
SelfCoin software in this repository is experimental and provided for technical evaluation.
This document is a protocol/implementation description and is not investment advice, financial advice, or legal advice.
Running nodes/validators involves operational and security risk; users and operators are responsible for their own key management and deployment decisions.
