# SelfCoin Core: Current Behavior (Repository-Grounded)

## Executive Summary
`selfcoin-core` is a C++20 deterministic settlement-chain implementation where blocks become valid only when a deterministic committee reaches BFT quorum (`floor(2N/3)+1`). The running node process is `selfcoin-node` (`apps/selfcoin-node/main.cpp`, `src/node/node.cpp`).

Coin ownership is UTXO-based and key-based: spendability is enforced by Ed25519 signatures over domain-separated sighashes (`src/utxo/validate.cpp::validate_tx`, `src/utxo/validate.cpp::signing_message_for_input`). There are no admin keys in consensus code paths; spending requires valid signatures or explicit validator-bond special rules.

Consensus uses deterministic leader selection and deterministic committee selection from finalized chain state only (`src/consensus/validators.cpp::select_leader`, `src/consensus/validators.cpp::select_committee`). Node progression is finalized-tip-only: proposals/votes are accepted only for `finalized_height + 1` (`src/node/node.cpp::handle_propose`, `src/node/node.cpp::handle_vote`).

Validator lifecycle is implemented on-chain via special scripts: bond registration (`SCVALREG`), unbond request (`SCVALUNB`) and slash/burn (`SCSLASH` evidence + `SCBURN`) with warmup/unbond-delay/banning rules (`src/utxo/tx.cpp`, `src/utxo/validate.cpp`, `src/consensus/validators.cpp`).
The intended live protocol scope is settlement-only: no VM, no general-purpose smart contracts, and no application-layer execution beyond the fixed UTXO and validator/bond forms.

Networking is TCP with strict framed messages, version/network identity checks, and hardening (timeouts, queue caps, token buckets, scoring, bans) (`src/p2p/framing.cpp`, `src/p2p/peer_manager.cpp`, `src/p2p/hardening.cpp`).

`selfcoin-lightserver` serves finalized-only JSON-RPC from DB indexes (`src/lightserver/server.cpp`) and can relay raw tx to a node over P2P.

Wallet-side integration is implemented via `spec/SELFCOIN_WALLET_API_V1.md` and TypeScript SDK `sdk/selfcoin-wallet-js`, where private keys stay client-side and signing is local (`sdk/selfcoin-wallet-js/src/wallet/SelfCoinWallet.ts`).

Mainnet identity/bootstrap exists with embedded genesis and network isolation; node verifies DB genesis marker consistency (`src/node/node.cpp::init_mainnet_genesis`, `src/genesis/embedded_mainnet.*`, `src/common/chain_id.cpp`).

The system is operationally deterministic and reproducible from finalized state, but decentralization level still depends on live validator/seed operator set (operational/infrastructure, not a consensus backdoor).

## Implementation Index
| Topic | Primary implementation |
|---|---|
| Node entry/CLI | `apps/selfcoin-node/main.cpp`, `src/node/node.cpp::parse_args` |
| Node runtime loop/finality | `src/node/node.cpp::event_loop`, `handle_propose`, `handle_vote`, `finalize_if_quorum` |
| Consensus leader/committee/quorum | `src/consensus/validators.cpp::select_leader`, `select_committee`, `quorum_threshold` |
| Vote tracking/equivocation | `src/consensus/votes.cpp::VoteTracker::add_vote` |
| Monetary policy/payout split | `src/consensus/monetary.cpp::reward_units`, `compute_payout` |
| Tx/block serialization + IDs | `src/utxo/tx.cpp::{Tx,BlockHeader,Block}::*` |
| Tx validation + special validator scripts | `src/utxo/validate.cpp::validate_tx`, `validate_block_txs` |
| Mempool | `src/mempool/mempool.cpp` |
| P2P framing + message codecs | `src/p2p/framing.cpp`, `src/p2p/messages.cpp` |
| P2P connection manager/hardening | `src/p2p/peer_manager.cpp`, `src/p2p/hardening.cpp` |
| AddrMan/bootstrap | `src/p2p/addrman.cpp`, `src/node/node.cpp::try_connect_bootstrap_peers` |
| Storage/indexes | `src/storage/db.cpp` |
| Lightserver JSON-RPC | `src/lightserver/server.cpp::handle_rpc_body` |
| Keystore/wallet file | `src/keystore/validator_keystore.cpp` |
| Chain identity/genesis checks | `src/common/network.cpp`, `src/common/chain_id.cpp`, `src/genesis/genesis.cpp`, `src/node/node.cpp::init_mainnet_genesis` |
| CLI tooling | `apps/selfcoin-cli/main.cpp` |
| Observer | `scripts/observe.py` |
| TypeScript SDK | `sdk/selfcoin-wallet-js/src/*` |

## 1) Repo Map and Responsibilities
- `apps/selfcoin-node/main.cpp`: process entry; parses node flags through `node::parse_args`, runs `Node::init/start/stop`.
- `apps/selfcoin-lightserver/main.cpp`: lightserver process entry; parses `lightserver::parse_args`.
- `apps/selfcoin-cli/main.cpp`: utility CLI (tip, keypair/wallet ops, tx builders, genesis tools, RPC status/compare, raw broadcast).
- `src/node/node.*`: orchestration: state load, keystore load/create, event loop, consensus flow, p2p handlers, persistence updates.
- `src/consensus/*`: validator registry/state transitions, deterministic leader/committee, quorum helper, vote tracker, monetary schedule.
- `src/utxo/*`: core chain objects + serialization, validation rules, signing helpers.
- `src/mempool/*`: tx admission/selection/remove/prune.
- `src/p2p/*`: frame protocol, message codec, peer manager, addrman, hardening.
- `src/storage/db.*`: RocksDB (or file fallback) key/value schemas for finalized chain state and indexes.
- `src/lightserver/*`: finalized-only HTTP JSON-RPC over DB.
- `src/genesis/*`: mainnet genesis doc/bin encode/decode/hash/validate and embedded genesis bytes.
- `src/keystore/*`: validator wallet file generation/loading (encrypted optional).
- `sdk/selfcoin-wallet-js/*`: non-custodial wallet SDK for lightserver integration.

## 2) Protocol Rules vs Node Operation
### Protocol rules (consensus-critical)
- Tx/Block/Vote serialization and IDs (`src/utxo/tx.cpp`).
- Signature/message rules and script rules (`src/utxo/validate.cpp`).
- Leader/committee/quorum functions (`src/consensus/validators.cpp`).
- Monetary reward schedule/split (`src/consensus/monetary.cpp`).

### Node operation (implementation/runtime)
- Startup, key management, peer bootstrap, event loop timing, relay behavior (`src/node/node.cpp`).
- Networking hardening and scoring policies (`src/p2p/hardening.cpp`, `src/p2p/peer_manager.cpp`).

## 3) Coin Ownership = Private Key (As Implemented)
### Locking model
- Standard spendable outputs are P2PKH scriptPubKey bytes: `76 a9 14 <20-byte-hash> 88 ac` (`src/utxo/validate.cpp::is_p2pkh_script_pubkey`, `src/address/address.cpp::p2pkh_script_pubkey`).
- Address encoding/decoding is custom base32 with `sha256d` 4-byte checksum over `hrp + 0x00 + payload`, HRP `sc`/`tsc` (`src/address/address.cpp`).
- Base-layer output script scope is intentionally narrow: P2PKH plus the existing validator register, validator unbond, and slash-burn forms.

### Unlocking model
- ScriptSig shape is strict: `0x40 <64-byte-sig> 0x20 <32-byte-pubkey>` (`src/utxo/validate.cpp::is_p2pkh_script_sig`).
- Sighash message = `sha256d("SC-SIG-V0" || u32_le(input_index) || sha256d(signing_tx_bytes_with_all_script_sig_empty))` (`src/utxo/validate.cpp::signing_message_for_input`).
- Ed25519 verify uses extracted pubkey (`src/utxo/validate.cpp::validate_tx`).

### Double-spend prevention
- In block validation: duplicate inputs in same tx rejected and missing-spent UTXOs rejected (`validate_tx`).
- In mempool: rejects if outpoint already spent by another mempool tx (`src/mempool/mempool.cpp::accept_tx` + `spent_outpoints_`).
- No unconfirmed-parent policy in mempool v0.x: every input must already exist in finalized UTXO view (`accept_tx`).

## 4) Consensus + Finality (Current)
### Finalized-chain-first operational meaning
- Node only accepts propose/vote for `height == finalized_height + 1` (`src/node/node.cpp::handle_propose`, `handle_vote`).
- Node does not build/track arbitrary unfinalized forks; candidate blocks are bounded cache keyed by `block_id` (`candidate_blocks_`).
- Research-only VRF and `sortition_v2` helpers remain in the repository but are not part of this active runtime path.

### Leader selection
- Deterministic from finalized hash + height + round + sorted active set (`src/consensus/validators.cpp::select_leader`).

### Committee selection
- Deterministic seed: `sha256d("SC-COMMITTEE-V0" || prev_finalized_hash || u64_le(height))`.
- Score each active validator by `sha256d(seed || pubkey)`, sort by `(score, pubkey)`, select first `min(max_committee, active_size)` (`src/consensus/validators.cpp::select_committee`).

### Voting/finality path
- Leader proposes full block (`Node::build_proposal_block`, `broadcast_propose`).
- Committee members sign `block_id` and produce vote (`Node::handle_propose` + `crypto::ed25519_sign`).
- Vote checks: height gate, committee membership gate, signature verify (with cache), dedupe/equivocation tracking (`Node::handle_vote`, `VoteTracker`).
- Finality condition: valid distinct committee signatures for same `(height,round,block_id)` >= quorum (`Node::finalize_if_quorum`, `consensus::quorum_threshold`).
- On finalization: persist block/indexes, apply validator changes, apply UTXO, prune mempool, reset round, broadcast finalized block (`Node::persist_finalized_block`, `apply_validator_state_changes`, `apply_block_to_utxo`).

### Timeout/liveness
- Round timeout increments round every `network.round_timeout_ms` if not finalized (`Node::event_loop`).
- Logs committee/quorum and periodic state summary (`Node::event_loop`).

### Equivocation handling
- VoteTracker emits equivocation when same validator signs different block_id at same `(height,round)` (`src/consensus/votes.cpp`).
- Node immediately bans equivocation validator if validator was committee member for that round (`Node::handle_vote`).

## 5) Validator Lifecycle and Slashing
### Register/bond
- Special output script `SCVALREG` + 32-byte pubkey (`src/utxo/tx.cpp::is_validator_register_script`).
- Value must equal `BOND_AMOUNT` (`src/utxo/validate.cpp::validate_tx`).
- Finalization state update registers validator as `PENDING` with bond outpoint (`src/consensus/validators.cpp::register_bond`, called from `Node::apply_validator_state_changes`).

### Warmup transition
- `PENDING -> ACTIVE` when `height >= joined_height + WARMUP_BLOCKS` in `ValidatorRegistry::advance_height` (`src/consensus/validators.cpp`).

### Unbond
- Spending bond via UNBOND path requires one output `SCVALUNB` with matching pubkey, one input auth signature over `SC-UNBOND-V0` message (`src/utxo/validate.cpp`, `unbond_message_for_input`).
- On finalized unbond tx, registry marks `EXITING` and `unbond_height`; removed from active (`request_unbond`, `advance_height`).
- Spending `SCVALUNB` output to normal P2PKH is blocked until `current_height >= unbond_height + UNBOND_DELAY_BLOCKS` (`validate_tx`).

### Slash
- Slash scriptSig marker `SCSLASH` + varbytes evidence blob of two fixed-size votes (`parse_slash_script_sig`).
- Evidence validity requires same height/round, different block_id, same validator, valid Ed25519 signatures, and committee membership callback true (`validate_tx`).
- Slash spend must produce exactly one `SCBURN` output with evidence hash (`is_burn_script` + checks in `validate_tx`).
- State effect on finalize path: spending a bond with slash evidence causes `validators_.ban(pub)` (`Node::apply_validator_state_changes`).

### Permissionless status
- Join path is on-chain via `SCVALJRQ` + matching bond output; finalized valid join requests are admitted automatically under rule checks and then warm up to active.
- Effective participation still depends on obtaining stake and surviving warmup/delay rules.
- Genesis initial validator set is configured at chain boot from genesis document (`Node::init_mainnet_genesis`).

## 6) UTXO, Transaction Validation, and Monetary Policy
### Tx/block primitives
- Tx/BlockHeader/Block/FinalityProof serialization is explicit field-by-field LE + ULEB128 varints (`src/utxo/tx.cpp`, `src/codec/*`).
- `txid = sha256d(tx.serialize())` (`Tx::txid`).
- `block_id = sha256d("SC-BLOCK-V0" || BlockHeader.serialize())` (`BlockHeader::block_id`).

### Coinbase and fees
- For non-coinbase tx: fee = `sum(inputs) - sum(outputs)`, must be non-negative (`validate_tx`).
- Block validation requires `coinbase_sum == reward_units(height) + total_fees` (`validate_block_txs`).

### Monetary schedule
- 7,000,000 coins cap in 1e8 base units, deterministic by height (`src/consensus/monetary.hpp/.cpp`).
- Emission block count and q/r split implemented exactly by integer math (`reward_units`).

### Deterministic payout split
- `leader = floor((reward+fees)*20/100)`.
- Remaining 80% split equally among sorted unique signer pubkeys; remainders to lowest-lex pubkeys (`compute_payout`).
- Block validator enforces coinbase output scripts/amounts match computed split when signer list is provided (`validate_block_txs` with `reward_signers`).

### UTXO updates
- Finalized block application only (`apply_block_to_utxo`) and persisted in DB in finalization path (`Node::persist_finalized_block`).

## 7) Node Operation and CLI
### Node flags (implemented parser)
- Network/profile: `--devnet | --testnet | --mainnet`.
- DB/genesis: `--db`, `--genesis`, `--allow-unsafe-genesis-override`.
- Identity/wallet: `--validator-key-file`, `--validator-passphrase`, `--validator-passphrase-env`.
- P2P/listen/bootstrap: `--port`, `--listen`, `--bind`, `--public`, `--outbound-target`, `--peers`, `--seeds`, `--dns-seeds/--no-dns-seeds`, `--disable-p2p`.
- Hardening/rate/bans: `--handshake-timeout-ms`, `--frame-timeout-ms`, `--idle-timeout-ms`, queue caps, `--max-inbound`, `--ban-seconds`, invalid-frame thresholds, `--min-relay-fee`, `--log-json`.
- Source: `src/node/node.cpp::parse_args`, usage string in `apps/selfcoin-node/main.cpp`.

### Default DB path and keystore
- If `--db` not set: `~/.selfcoin/<network>` (`src/common/paths.cpp::default_db_dir_for_network`, wired in `parse_args`).
- Mainnet (or explicit key file): node loads/creates keystore at `<db>/keystore/validator.json` by default (`Node::init`, `keystore::default_validator_keystore_path`).

## 8) P2P Networking and Hardening
### Framing and handshake
- Frame: `magic(u32le), proto(u16le), msg_type(u16le), payload_len(u32le), payload, checksum=sha256d(payload)` (`src/p2p/framing.cpp`).
- VERSION payload includes protocol, network_id, feature_flags, services, software version, tip (`src/p2p/messages.cpp::ser_version`).
- Node rejects on network_id mismatch and protocol mismatch before establishment (`Node::handle_message` VERSION branch).
- Non-handshake messages before established VERACK/VERSION are rejected/scored (`handle_message`).

### Message set
- Implemented: `VERSION, VERACK, GET_FINALIZED_TIP, FINALIZED_TIP, GET_BLOCK, BLOCK, PROPOSE, VOTE, TX, GETADDR, ADDR` (`src/p2p/messages.hpp`).

### Bootstrap/sync behavior
- Sources merged: explicit peers, explicit seeds, network default seeds, DNS-resolved seeds, addrman candidates (`Node::init`, `resolve_dns_seeds_once`, `try_connect_bootstrap_peers`).
- Sync strategy is finalized-tip exchange and block-by-hash fetch (`Node::handle_message` GET/FINALIZED_TIP/BLOCK).

### Hardening
- Connection deadlines: handshake/frame/idle timeouts (`PeerManager::Limits`, `read_frame_fd_timed` usage).
- Per-peer outbound queue caps with low-priority drop for TX and disconnect on overflow (`PeerManager::send_to`).
- Rate limiting token buckets by message class (`Node::check_rate_limit_locked` + `TokenBucket`).
- Misbehavior scoring/soft-mute/ban with invalid-frame strike window (`PeerDiscipline`).
- Frame-failure diagnostics classify HTTP/JSON/TLS/magic mismatch (`PeerManager::frame_fail_detail`, `Node` event handler logs).

## 9) State and Storage
### Core keys/indexes
- Tip: `T:` (`DB::set_tip/get_tip`).
- Block bytes: `B:<hash>`; height->hash: `H:<u64le-hex>`.
- UTXO: `U:<outpoint-hex>`.
- Validators: `V:<pubkey-hex>`.
- Tx index: `X:<txid-hex>` -> `(height,tx_index,tx_bytes)`.
- Lightserver script indexes:
  - `SU:<scripthash>:<outpoint>` -> UTXO tuple.
  - `SH:<scripthash>:<height_be>:<txid>` -> history entry.
- Genesis markers: `G:` (genesis hash), `GB:` (genesis block id), set by node mainnet init (`Node::init_mainnet_genesis`).

### Finalized-only persistence rule
- Node writes tx indexes/script indexes only during block finalization path (`Node::persist_finalized_block`).

## 10) Lightserver and Wallet API Integration
### Implemented RPC methods
- `get_tip`, `get_status`, `get_headers`, `get_header_range`, `get_block`, `get_finality_certificate`, `get_tx`, `get_utxos`, `get_committee`, `get_roots`, `get_utxo_proof`, `get_validator_proof`, `broadcast_tx` (`src/lightserver/server.cpp::handle_rpc_body`).
- `get_status` includes chain identity fields (`network_name`, `protocol_version`, `feature_flags`, `network_id`, `magic`, `genesis_hash`, `genesis_source`, `chain_id_ok`) and tip/uptime.

### Finalized-only semantics
- Reads tip/blocks/tx/UTXO from DB finalized indexes only.
- `broadcast_tx` validates against current DB UTXO snapshot and relays via P2P TX to configured node (`Server::relay_tx_to_peer`), does not maintain mempool itself.
- `get_header_range` is implemented alongside `get_headers` and is bounded by the same request-size caps.
- `get_finality_certificate` accepts lookup by finalized height, finalized block hash, or current finalized tip when no selector is provided.
- `get_roots` / `get_utxo_proof` / `get_validator_proof` are read surfaces over locally stored finalized roots/SMT state. In the current fixed runtime, proofs are tip-only and historical proof requests are rejected.

### Finality certificate surface
- Finalized blocks still expose embedded `finality_proof` data in block/header-oriented responses.
- Lightserver also exposes a separate `get_finality_certificate` RPC that returns the persisted raw-signature finality certificate for a finalized block by height, by block hash, or by current finalized tip.
- The current certificate object carries explicit committee members and raw signatures derived from the finalized quorum result already used by the runtime.
- This is a durability/readability improvement, not a new consensus object with header commitment or aggregated signatures.

### Scripthash definition
- `scripthash = sha256(script_pubkey)` (single SHA256), used for index keys (`Node::persist_finalized_block` computes with `crypto::sha256`).

### Wallet API v1 contract
- Documented in `spec/SELFCOIN_WALLET_API_V1.md`; methods match current lightserver method names.
- Note: `spec/SELFCOIN_WALLET_API_V1.md` documents the wallet-facing subset. The lightserver also exposes certificate and proof-oriented methods beyond that subset.

## 11) TypeScript SDK Behavior
### Non-custodial key/signing
- Key generation/import and signing are local in SDK process (`SelfCoinWallet.generateKeypair/importPrivkeyHex`, `tx/signInputP2PKH`).
- No private key RPC transmission in SDK codepaths.

### Address/script/scripthash
- Address derivation mirrors C++ (`sdk/.../address/index.ts`).
- P2PKH script builder mirrors C++ byte pattern (`sdk/.../script/index.ts`).
- Scripthash uses single SHA256 (`scriptHashHex`).

### Tx build/sign/broadcast
- Deterministic UTXO coin selection: sort by value desc, txid asc, vout asc (`wallet/coinSelection.ts`).
- Build tx, sign each input with `SC-SIG-V0` message, serialize canonical LE+varint (`sdk/.../tx/tx.ts`).
- Broadcast via lightserver `broadcast_tx`, then poll `get_tx` for finality (`SelfCoinWallet.sendTransaction`, `waitForFinality`).

### Multi-server trust mitigation
- Optional quorum tip cross-check mode in RPC client (`LightServerClient.getTip`, `quorumMode='cross-check-tip'`).

## 11.5) Snapshot Export / Import (Implementation-First)
- `selfcoin-cli snapshot_export --db <dir> --out <snapshot>` exports a deterministic bundle of the finalized-state DB namespaces needed for restart/recovery/import.
- `selfcoin-cli snapshot_import --db <empty-dir> --in <snapshot>` imports that bundle into an empty DB using the ordinary runtime keyspace.
- The snapshot bundle carries finalized metadata, height/block indexes, certificates, UTXO/validator state, script indexes, root records, SMT state, and validator/liveness metadata.
- In this first slice, snapshot export is an offline/quiescent-DB tool. It is not yet positioned as a live hot-backup mechanism.
- This is not trust-minimized protocol fast sync. The active finalized block/header path does not currently commit the state roots/checkpoints strongly enough to make that claim.

## 11.6) Recent Stability Note
- The recurring late full-suite test crash was traced to local-bus teardown in test/runtime plumbing, not to deterministic settlement rules.
- The conservative fix aligned local-bus vote delivery with the same shutdown guards used for other peer-delivered traffic and tightened teardown ordering around DB close.
- A follow-on timing-sensitive committee test was also narrowed to compare an explicit fixed `(height, round)` pair instead of a moving per-node round helper.

## 12) Genesis, Bootstrap Trust, and “No Owner/Admin” Analysis
### Genesis/mainnet loading
- Mainnet uses embedded genesis if `--genesis` omitted (`Node::init_mainnet_genesis`, `src/genesis/embedded_mainnet.*`).
- On empty DB: writes genesis marker and sets tip height 0 to genesis block id; seeds initial validators from genesis document as ACTIVE.
- On existing DB: verifies stored genesis marker/hash and genesis tip consistency; startup fails on mismatch.

### Admin/owner pathways in current code
- No consensus admin key path found in tx validation, consensus finalize path, or lightserver RPC.
- Movement of coins remains signature-gated by script rules (or validator bond special consensus paths).

### Neutrality decomposition
- Custody neutrality: implemented (no privileged spend path without keys), except explicit slash/unbond consensus rules tied to validator bonds.
- Network neutrality: constrained by current validator set composition and who runs validators; this is operational decentralization, not hidden control API.
- Upgrade control: no on-chain governance mechanism implemented; software upgrades are social/coordinated deployment process.

## 13) Security and Decentralization: Current Honest Assessment
### Strong today
- Deterministic, reproducible finalization logic and committee derivation.
- Strict network identity checks (network_id + protocol + magic framing).
- Bounded caches/queues + rate limits + ban model against common P2P abuse.
- Finalized-only serving path for light clients reduces reorg-surface complexity.

### Not solved / limits today
- Leader is deterministic/predictable (no VRF/private leader election).
- Sybil/capture resistance depends on economic bond model and real operator distribution, not anonymity-resistant peer identity.
- Light clients still trust lightserver data unless cross-checking or independently verifying proofs/history.
- No proof-carrying state protocol for full trustless mobile sync in current RPC surface.
- No built-in automatic validator key backup/HSM; keystore is file-based (encrypted optional, unencrypted allowed if passphrase empty).

## 14) Implemented vs Not Implemented (Observed)
### Implemented
- Finalized-chain BFT with deterministic leader/committee/quorum.
- Bond/unbond/slash validator lifecycle rules.
- UTXO + strict P2PKH validation + mempool + tx gossip.
- Lightserver finalized-only APIs + TypeScript non-custodial SDK.
- Mainnet profile + embedded genesis + chain-identity diagnostics.

### Not implemented / absent in code
- No GUI wallet in `selfcoin-core` binaries.
- No PoW mining path.
- No smart-contract VM/opcode engine beyond fixed script patterns.
- No generic account model.
- No trustless light-client proof protocol beyond current finalized-index API and committee/header data.
- `get_script_history` exists in DB API (`DB::get_script_history`) but is not exposed as lightserver RPC method in `Server::handle_rpc_body`.

## 15) Open Questions / TODOs Found in Code
- `validate_block_txs` takes `block_reward` parameter but uses height-based `reward_units` and explicitly ignores `block_reward` (`(void)block_reward`), which is harmless but confusing (`src/utxo/validate.cpp::validate_block_txs`).
- Lightserver `get_status` returns nested `tip` object; CLI `rpc_status` parser currently expects top-level `height/hash` fields in its parser helper (`apps/selfcoin-cli/main.cpp::parse_get_status_result`). This should be verified in runtime behavior.
- Mainnet seed list currently includes concrete IP/host values in code (`src/common/network.cpp`). Operational trust/bootstrap quality depends on whether those endpoints are maintained and diverse.
