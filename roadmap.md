# selfcoin-core Roadmap

## Project Direction

`selfcoin-core` is being narrowed into a deterministic settlement-chain implementation.

The active design goal is not feature breadth. The goal is a boring, explicit, auditable base layer with:

- deterministic final settlement
- cheap validation
- strong full-node clarity
- finalized-only operational flow
- lightserver support for read-heavy clients
- a smaller conceptual and operational surface

This roadmap treats the current shipped deterministic runtime as the baseline that must be preserved unless a phase explicitly introduces a tightly scoped protocol change.

## Current State of the Repo

Repo-grounded observations from the current codebase:

- Active runtime consensus is deterministic:
  - proposer selection is deterministic in `src/consensus/validators.cpp`
  - committee selection is deterministic in `src/consensus/validators.cpp`
  - votes are committee-membership based in `src/node/node.cpp`
  - quorum is `quorum_threshold(committee.size())`
- Blocks already carry an embedded `FinalityProof` in `src/utxo/tx.hpp` / `src/utxo/tx.cpp`.
- Finalization is currently materialized in `Node::finalize_if_quorum` in `src/node/node.cpp`.
- Finalized state is persisted explicitly in `src/storage/db.cpp`.
- UTXO and validator state roots are computed and stored locally in DB in `src/node/node.cpp` and `src/consensus/state_commitment.cpp`.
- Lightserver already serves finalized-only read APIs in `src/lightserver/server.cpp`.
- The transaction model already aligns with a narrow settlement chain:
  - fixed tx version
  - fixed `lock_time`
  - strict P2PKH
  - validator register / unbond / slash-burn paths in `src/utxo/validate.cpp`
- Remaining ambiguity still exists:
  - research/non-runtime VRF code in `src/crypto/vrf.*`
  - research/non-runtime `sortition_v2` helpers in `src/consensus/validators.*`
  - research tests in `tests/test_vrf.cpp` and `tests/test_sortition_v2.cpp`
  - docs that still describe more protocol surface than the live runtime needs
  - historical state-commitment naming in `src/consensus/state_commitment.*`
- Snapshot-style fast sync is not trust-minimized today because active state roots are not committed in the live finalized block/header path.
- Custom-genesis single-node bootstrap is now supported in a narrow form:
- Custom-genesis bootstrap mode now supports small-network growth in a narrow form:
  - `selfcoin-cli genesis_build` / `genesis_verify` accept an empty-validator custom genesis template
  - `selfcoin-node` loads or creates the local validator keystore before genesis init
  - on first start only, a custom genesis with `initial_validators = []` is bound to that local validator as the sole active validator
  - later fresh nodes started from the same template adopt the running network's bootstrap validator and sync to the same chain identity
  - the bootstrap validator can sponsor later peer validator keys with real on-chain `SCVALREG` bond transactions once enough mined rewards exist, so later nodes can become validators after the normal warmup
  - bootstrap-template mode now ignores stale `peers.dat` / `addrman` state until a bootstrap validator is known, uses explicit seeds first, and waits longer before self-bootstrapping when public bootstrap sources exist
  - embedded built-in mainnet genesis remains unchanged

## Target Protocol Identity

Target identity for the live protocol:

- SelfCoin is a deterministic settlement chain.
- The base layer is for value transfer and validator/bond lifecycle operations.
- Full-node validation must stay compact, explicit, and easy to audit.
- Finality is explicit and durable.
- Light clients use finalized data only.
- No general-purpose VM.
- No Ethereum-like application runtime.
- No ambiguity between research code and live protocol code.

## Prioritized Roadmap Phases

### Phase 1: Lock the Protocol Around Settlement-Only Execution

Goal:
- remove or clearly isolate ambiguity around non-runtime/research surfaces
- tighten docs and invariants
- make the repo tell the truth about the active protocol scope

### Phase 2: Add First-Class Finality Certificates Conservatively

Goal:
- add a separate raw-signature `FinalityCertificate` object
- persist it separately
- expose it through lightserver
- preserve current embedded `Block.finality_proof` behavior initially

### Phase 3: Add Snapshot Infrastructure Implementation-First

Goal:
- deterministic snapshot export/import for finalized state
- no false claim of trust-minimized protocol sync until chain-committed checkpoint/state-root work exists

## Exact Tasks Per Phase

### Phase 1 Tasks

1. Inventory and isolate ambiguity
- identify all research/non-runtime surfaces that can be confused with active protocol code
- classify each as:
  - active runtime
  - research helper
  - historical naming
  - docs ambiguity

2. Lock protocol invariants in tests
- add tests that assert:
  - tx version remains fixed
  - nonzero `lock_time` is rejected
  - unsupported base-layer script forms are rejected
  - only the existing settlement-oriented script families are accepted in validation paths

3. Clarify code surfaces
- mark VRF and `sortition_v2` helpers as research-only / non-runtime
- ensure comments and naming do not imply those surfaces are part of the active consensus path
- avoid changing active runtime behavior

4. Tighten docs
- update `README.md`
- update `docs/runtime-consensus.md`
- update `docs/SELFCOIN_CORE_CURRENT_BEHAVIOR.md`
- add explicit out-of-scope statements for:
  - no VM
  - no general-purpose smart contracts
  - no general asset/app-layer execution in base layer

5. Keep Phase 1 minimal
- do not redesign tx validation
- do not remove working code that may still be useful for later phases unless the removal is clearly behavior-neutral

### Phase 2 Tasks

1. Introduce `FinalityCertificate`
- define a separate certificate type with:
  - height
  - round
  - block hash
  - quorum threshold
  - deterministic committee context or committee members
  - raw signature set

2. Build certificates from current runtime material
- construct in `Node::finalize_if_quorum`
- reuse the already filtered quorum signatures

3. Persist certificates separately
- add a DB keyspace for certificates
- store by height and/or block hash

4. Expose certificates
- add lightserver endpoint(s) for certificate retrieval
- preserve existing block/finality proof surfaces where practical

5. Preserve compatibility
- keep `Block.finality_proof` initially
- do not introduce aggregated signatures
- do not change current finalization semantics unless required by the conservative certificate extraction itself

### Phase 3 Tasks

1. Define deterministic snapshot bundle format
- conservative Phase 3 schema:
  - snapshot magic + format version
  - manifest with:
    - genesis hash
    - genesis block id
    - finalized height / hash
    - UTXO root at finalized height
    - validator root at finalized height
    - exact entry counts by finalized-state namespace
  - lexicographically sorted key/value entries for the finalized-state namespaces the runtime already persists
- initial included namespaces:
  - exact keys: `G:`, `GB:`, optional `G:J`, `T:`
  - prefixes: `H:`, `B:`, `FC:H:`, `FC:B:`, `U:`, `V:`, `X:`, `SU:`, `SH:`, `ROOT:`, `SMTL:utxo:`, `SMTL:validators:`, `SMTR:utxo:`, `SMTR:validators:`, `PV4:`

2. Implement export
- export the deterministic finalized-state keyspace into one snapshot bundle file
- compute manifest values from the live DB contents at finalized tip
- keep the format backend-neutral instead of exporting RocksDB internals
- treat export as a quiescent/offline DB operation in the first slice rather than a live hot-backup promise

3. Implement import
- import only into an empty DB
- validate manifest consistency before writing:
  - required keys exist
  - finalized tip in manifest matches `T:`
  - finalized roots in manifest match `ROOT:` records
  - entry ordering/counts are valid
- write imported entries as ordinary DB keys so existing node startup can load them without a new runtime path

4. Smallest safe implementation sequence
- add `storage/snapshot.*` with manifest/bundle types and export/import helpers
- add utility CLI commands for local snapshot export/import
- add tests for:
  - manifest/bundle parse roundtrip
  - export/import DB roundtrip
  - empty-DB-only import rejection
  - node startup against an imported snapshot DB

5. Keep trust model honest
- document that this is implementation-first fast recovery/sync
- explicitly state that snapshots are not trust-minimized protocol sync because the active finalized block/header path does not commit the state roots/certificates needed for that claim

## Risks / Migration Concerns

### Phase 1
- Over-deleting research code could create unnecessary churn if a later phase still wants those helpers for experiments.
- Documentation cleanup can accidentally overstate capabilities if not kept repo-grounded.

### Phase 2
- A certificate object is safe if extracted from existing finalization material.
- A header-committed certificate format would be a deeper consensus-format migration and is not part of conservative Phase 2.
- Lightserver/API additions must not imply stronger verification guarantees than the runtime actually provides.
- The safest committee context for the conservative certificate slice is the explicit committee member list. The repo does not yet have a separate chain-committed committee hash primitive for certificates.
- Standalone P2P certificate distribution is not required for the first conservative slice because finalized blocks already propagate and the runtime already embeds `Block.finality_proof`.

### Phase 3
- Current active roots are locally persisted, not actively committed by finalized block/header semantics.
- Snapshot import must include enough metadata to preserve validator/liveness state deterministically.
- RocksDB/file-backend differences may affect snapshot format design.
- Proof-capable state is not just `ROOT:` records; the live runtime also persists SMT leaves/root history under `SMTL:*` and `SMTR:*`, so those namespaces must either be carried or rebuilt.
- Quiescent/offline export is the safe first-slice assumption; live snapshotting against an actively advancing RocksDB node is intentionally not promised here.

### Test Runtime Stability
- The recurring late full-suite `EXIT:139` was traced to local-bus test transport teardown rather than protocol logic.
- Root cause: disable-P2P local-bus vote relays called `handle_vote(..., false, ...)`, which bypassed the node `running_` guard used for network-originated traffic. During cluster teardown, a queued local-bus vote task could therefore execute against a stopped node after `DB::close()`, leading to a null RocksDB handle access.
- Conservative fix: local-bus peer vote delivery now uses the same network-originated path guard as other peer-delivered messages.
- Follow-on stability finding: the snapshot bootstrap test also depended on finalized state roots being present at the current tip and on RocksDB readonly reopen succeeding immediately after stop. The conservative resolution was:
  - persist finalized state roots at each finalized tip
  - use the same readonly-or-writable fallback in the test that the CLI already uses for quiescent snapshot export
- Follow-on surfaced test issue: `test_committee_selection_and_non_member_votes_ignored` compared `committee_for_next_height_for_test()` across nodes after only synchronizing finalized height. That helper includes each node's live `current_round_`, so the assertion was timing-sensitive rather than protocol-grounded. Conservative resolution: the test now compares committee membership for an explicit fixed `(height, round)` pair.

## Acceptance Criteria Per Phase

### Phase 1
- active docs describe SelfCoin as a deterministic settlement chain
- Phase 1 invariants are covered by tests
- VRF / `sortition_v2` surfaces no longer appear to be active runtime consensus code
- no consensus behavior change

### Phase 2
- separate `FinalityCertificate` type exists
- certificates are built from current finalized vote material
- certificates are persisted separately
- certificates are exposed by lightserver
- existing runtime finalization behavior remains unchanged

### Phase 3
- deterministic snapshot export exists
- deterministic snapshot import exists
- startup can load imported finalized state
- docs clearly distinguish implementation-first snapshots from trust-minimized protocol sync

## Files / Modules Likely Affected

### Phase 1
- `README.md`
- `docs/runtime-consensus.md`
- `docs/SELFCOIN_CORE_CURRENT_BEHAVIOR.md`
- `src/utxo/validate.hpp`
- `src/utxo/validate.cpp`
- `src/consensus/validators.hpp`
- `src/crypto/vrf.hpp`
- `tests/test_main.cpp`
- `tests/test_vrf.cpp`
- `tests/test_sortition_v2.cpp`
- a new protocol-scope/invariants test file if needed

### Phase 2
- `src/utxo/tx.hpp`
- `src/utxo/tx.cpp`
- `src/node/node.hpp`
- `src/node/node.cpp`
- `src/storage/db.hpp`
- `src/storage/db.cpp`
- `src/lightserver/server.hpp`
- `src/lightserver/server.cpp`
- related tests

### Phase 3
- `src/storage/snapshot.hpp`
- `src/storage/snapshot.cpp`
- `apps/selfcoin-cli/main.cpp`
- related tests and docs
- existing node/storage/lightserver modules should remain unchanged unless the first slice reveals a concrete gap in imported-state startup
- related tests and docs

## Test Plan

### Phase 1
- targeted validation tests for protocol scope invariants
- existing runtime characterization tests
- full suite

### Phase 2
- certificate serialization / persistence tests
- finalization path tests ensuring certificates are built from current quorum signatures
- lightserver certificate endpoint tests
- full suite

### Phase 3
- snapshot export/import roundtrip tests
- restart/bootstrap tests from imported snapshot
- root/manifest verification tests
- full suite

## Deferred / Explicitly Out-of-Scope Items

- aggregated signatures
- BLS or future quorum cryptography redesign
- trust-minimized protocol fast sync before state/checkpoint commitments exist
- general-purpose VM execution
- smart-contract platform work
- Ethereum-like application-layer execution
- broad asset framework unless separately designed as a narrow settlement primitive
- weighted/VRF proposer or voter activation

## Roadmap Status

- Phase 1: complete for the current branch scope
  - completed:
    - ambiguity inventory for active runtime vs research surfaces
    - settlement-only protocol docs tightened in `README.md`, `docs/runtime-consensus.md`, and `docs/SELFCOIN_CORE_CURRENT_BEHAVIOR.md`
    - validation now explicitly rejects unsupported base-layer output scripts
    - research VRF / `sortition_v2` tests are labeled as research-only rather than active runtime coverage
    - protocol-scope invariants were added to the test suite
  - intentionally not continued in this branch stage:
    - further isolation of research-only helpers if a later branch wants a stricter module boundary
- Phase 2: current conservative slice complete
  - completed in this slice:
    - standalone raw-signature `FinalityCertificate` added
    - certificates are built from existing finalized vote/signature material
    - certificates are persisted separately by height and block hash
    - lightserver exposes certificates separately
    - embedded `Block.finality_proof` remains in place for compatibility
    - docs now describe separate certificate retrieval and lightserver supports tip-default certificate lookup
  - remaining in Phase 2:
    - decide whether the certificate RPC surface needs broader index/query support
    - document certificate persistence and retrieval semantics more explicitly if future client work depends on them
  - explicitly deferred in this slice:
    - header commitment of certificates
    - aggregated signatures
    - standalone P2P certificate distribution
- Phase 3: first slice in place
  - completed in this slice:
    - deterministic snapshot bundle format with explicit finalized-state namespace counts
    - storage-level export/import helpers
    - CLI utility surface for local snapshot export/import
    - empty-DB-only import guard
    - tests for bundle roundtrip, empty-db-only import rejection, and node startup from imported snapshot state
  - remaining in Phase 3:
    - decide whether snapshot-aware operational docs need a separate concise document beyond the README/current-behavior notes
    - decide whether later phases should add incremental delta/export tooling after checkpoint/state-root commitment work exists
  - explicitly deferred in the first slice:
    - protocol-grade checkpointed fast sync
    - incremental delta sync
    - trust-minimized verification claims
- Stability pass:
  - diagnosed the recurring late full-suite segfault as a local-bus vote-delivery teardown bug
  - fixed by routing disable-P2P peer vote delivery through the guarded network-originated path
  - full plain test suite now completes with `EXIT:0`
- Deployment/bootstrap hardening pass:
  - bootstrap-template startup now exposes bootstrap diagnostics through `NodeStatus` and summary logging:
    - established peer count
    - whether template-bootstrap mode is active
    - adopted bootstrap validator pubkey
    - pending sponsored bootstrap join count
  - bootstrap outbound connection preference now preserves source priority:
    - explicit peers/seeds first
    - DNS seeds second
    - addrman candidates last
  - README now documents the supported public bootstrap shape for the current template-based mainnet flow:
    - same `genesis.bin` on every node
    - live bootstrap endpoints in `mainnet/SEEDS.json`
    - fresh DB on first join
  - bootstrap-template behavior now distinguishes first-node bootstrap from follower join explicitly:
    - a node started without configured bootstrap peers/seeds may self-bootstrap
    - a seeded node waits for existing network adoption and no longer self-bootstraps into a separate fork
- Follow-on aggregate-suite stability pass:
  - the remaining late-run failures were not new protocol bugs; they were test/runtime coordination issues
  - root causes:
    - `test_committee_selection_and_non_member_votes_ignored` tried to align 12 live nodes on the exact same height before pausing proposals, which is timing-sensitive under normal forward progress
    - `tests/test_lightserver.cpp` manually stopped cluster nodes and then allowed the cluster destructor to stop them again, creating a late teardown hazard
    - the bootstrap sync integration tests were listener-dependent and need to tolerate late-suite socket exhaustion the same way other network tests in the repo already do
  - conservative fixes:
    - freeze proposal production before waiting for a stable shared tip in the committee-selection test
    - clear lightserver test clusters after manual stop so nodes are not stopped twice
    - make the bootstrap sync integration tests skip cleanly if the late-suite environment cannot reserve/bind a listener port
  - result:
    - full suite now completes with `EXIT:0`

- Current branch stage:
  - post-cleanup
  - post-hardening
  - pre-next-protocol-step
  - safe work at this stage should prioritize legibility, release readiness, and behavior-preserving internal cleanup rather than new protocol scope
