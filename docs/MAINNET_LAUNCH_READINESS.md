# MAINNET LAUNCH READINESS

## Owner Checklist (Go/No-Go)
- [ ] Full build succeeds from clean checkout.
- [ ] `ctest` passes reliably (including repeated runs).
- [ ] ASan/UBSan build is clean.
- [ ] Lightserver uses strict JSON parsing + RPC rate limiting (no regex parser path in production).
- [ ] Seed/bootstrap infrastructure is live and externally reachable.
- [ ] Monitoring/alerts are configured and tested.
- [ ] Genesis launch policy is `cv1` with activation disabled.
- [ ] Post-genesis activation governance/runbook is approved.

## Why `cv1..cv7` Exists (Consensus Safety Checkpoints)
`cv1..cv7` exists so protocol changes activate in controlled steps instead of hard-forking instantly.

- Different rules change block validity (for example: v2/v5/v6/v7 proposer/voter eligibility, v3 state commitments).
- Activation makes upgrades deterministic: nodes on the same finalized chain and same signaling windows switch at the same height (`version_for_height` in `src/consensus/activation.cpp`).
- This creates rollback/canary room: default runtime can stay on `cv1`; upgrades are enabled only when operators are ready.

## Activation Policy At Genesis
- Mainnet launch mode must be `activation_enabled=false` by default (`src/common/network.cpp`).
- Genesis launch target is **cv1 only**.
- No automatic jump to cv7 at genesis.
- Activation of higher CVs requires explicit governance process and staged rollout:
  1. Canary validators (small set) on rehearsal environment.
  2. Mixed-version compatibility matrix check.
  3. Public activation height/window announcement.
  4. Staged enablement and monitoring.
  5. Abort/hold criteria documented before activation starts.

---

## A) CURRENT CAPABILITIES

### Consensus
- Finalized-chain-first operation is implemented (`src/node/node.cpp`):
  - proposal/vote acceptance is restricted to `finalized_height + 1` in `handle_propose`, `handle_vote`.
  - finalization path is `finalize_if_quorum`.
- Quorum rule is `floor(2N/3)+1` (`src/consensus/validators.cpp::quorum_threshold`).
- Activation framework is implemented (`src/consensus/activation.cpp`) and wired in node (`src/node/node.cpp`).
- Gated consensus paths are present:
  - v2 randomized committee/leader (`src/consensus/validators.cpp`, node committee/leader paths).
  - v3 commitment checks (`src/consensus/state_commitment.cpp`, `src/node/node.cpp`).
  - v4 validator/liveness rules (`src/consensus/validators.cpp`, `src/node/node.cpp`).
  - v5 private sortition transcript-bound VRF-like checks (`src/consensus/sortition_v5.cpp`, `src/crypto/vrf.cpp`, `src/node/node.cpp`).
  - v6 weighted eligibility (`src/consensus/sortition_v6.cpp`, `src/node/node.cpp`).
  - v7 variable bond + effective cap usage (`src/utxo/validate.cpp`, `src/consensus/validators.cpp`, `src/node/node.cpp`).
- Equivocation detection exists in vote tracker (`src/consensus/votes.cpp`) and ban path in node vote handling (`src/node/node.cpp`).

### State model and persistence
- UTXO + finalized block persistence are implemented (`src/node/node.cpp::persist_finalized_block`).
- DB stores tip, blocks, height index, tx index, UTXO, script indexes, validators, activation state (`src/storage/db.cpp`).
- Genesis identity and mismatch protection are implemented (`src/node/node.cpp::init_mainnet_genesis`, `src/common/chain_id.cpp`).
- v3 state roots (UTXO/validator) are persisted and checked against SCR3 marker (`src/consensus/state_commitment.cpp`, `src/node/node.cpp`).

### Transactions and validation
- Deterministic tx/block serialization and IDs are implemented (`src/utxo/tx.cpp`).
- Strict P2PKH validation and sighash domain separation (`SC-SIG-V0`) are implemented (`src/utxo/validate.cpp`).
- Validator scripts supported: `SCVALREG`, `SCVALUNB`, `SCSLASH`, `SCBURN` (`src/utxo/tx.cpp`, `src/utxo/validate.cpp`).
- Coinbase reward/fees distribution checks exist (`src/utxo/validate.cpp`, `src/consensus/monetary.cpp`).

### Networking
- Frame protocol with magic/version/checksum/length checks (`src/p2p/framing.cpp`).
- VERSION handshake includes protocol/network identity/feature flags (`src/p2p/messages.*`, `src/node/node.cpp`).
- Cross-network and unsupported protocol rejection is implemented (`src/node/node.cpp`).
- AddrMan + GETADDR/ADDR + persistence with policy filters (required mainnet port, unroutable rejection) are implemented (`src/p2p/addrman.*`, `src/node/node.cpp`).
- Misbehavior scoring, soft-mute, ban thresholds implemented (`src/p2p/hardening.cpp`).

### Light clients / lightserver / SDK
- Lightserver endpoints implemented in `src/lightserver/server.cpp`:
  - `get_status`, `get_tip`, `get_headers`, `get_header_range`, `get_block`, `get_tx`, `get_utxos`, `get_committee`, `get_roots`, `get_utxo_proof`, `get_validator_proof`, `broadcast_tx`.
- SMT proof responses (`smt_v0`) and root fields are implemented.
- TS SDK supports non-custodial wallet operations and trustless verification mode:
  - finality verification (`sdk/selfcoin-wallet-js/src/proofs/finality.ts`)
  - SMT proof verification (`sdk/selfcoin-wallet-js/src/proofs/smt.ts`)
  - trustless balance flow (`sdk/selfcoin-wallet-js/src/wallet/SelfCoinWallet.ts`).

### Node ops
- Mainnet-only runtime and defaults are in `src/common/network.cpp`.
- Default DB path is network-scoped (`src/common/paths.cpp`, node/lightserver arg parsing).
- Embedded mainnet genesis is used by default (`src/genesis/embedded_mainnet.cpp`, `src/node/node.cpp`).
- Keystore support (encrypted and optional no-passphrase) is implemented (`src/keystore/validator_keystore.cpp`).

---

## B) MAINNET LAUNCH CHECKLIST (Missing Work)

## 1) Protocol correctness and safety
- [ ] Eliminate flaky segfault in full `ctest` run.
  - Why: nondeterministic crashes are consensus/ops risk.
  - Files: `tests/*`, `src/node/node.cpp`, `src/p2p/peer_manager.cpp`.
  - Minimal tests: repeated `ctest` loop + sanitizer runs.
  - Launch blocker: **YES**.

- [ ] Add replay/activation boundary stress tests for cv transitions.
  - Why: boundary bugs can split consensus.
  - Files: `src/consensus/activation.cpp`, `tests/test_activation.cpp`, `tests/test_integration.cpp`.
  - Minimal tests: randomized signaling streams + restart/replay equivalence.
  - Launch blocker: **YES**.

## 2) Networking hardening and DoS resistance
- [ ] Add stronger per-peer CPU budgets for expensive validation paths.
  - Files: `src/node/node.cpp`, `src/p2p/peer_manager.cpp`.
  - Tests: flood invalid propose/block/tx and assert liveness remains.
  - Launch blocker: **YES**.

- [ ] Eclipse/Sybil bootstrap hardening validation.
  - Files: `src/p2p/addrman.cpp`, `src/node/node.cpp`.
  - Tests: adversarial ADDR injection simulation.
  - Launch blocker: **YES**.

## 3) Economic/security assumptions
- [ ] Parameter calibration for v4-v7 (bond caps, liveness thresholds, weight caps).
  - Files: `src/common/network.cpp`, docs under `docs/`.
  - Tests: deterministic simulation harness in tests.
  - Launch blocker: **YES**.

## 4) Data integrity and storage
- [ ] Crash-recovery torture tests (power-loss/restart loops).
  - Files: `src/storage/db.cpp`, `src/node/node.cpp`, integration tests.
  - Tests: kill/restart loop + state/root consistency.
  - Launch blocker: **YES**.

## 5) Lightserver production hardening
- [ ] Replace regex JSON parsing with strict JSON parser + schema validation.
  - Files: `src/lightserver/server.cpp` (`find_string`, `find_u64`, `find_id_token`, request parsing flow).
  - Tests: malformed JSON corpus; parser differential tests.
  - Launch blocker: **YES**.

- [ ] Add RPC rate limiting and request bounds.
  - Files: `src/lightserver/server.cpp`.
  - Tests: high-rate abuse tests with bounded latency/resource usage.
  - Launch blocker: **YES**.

## 6) Wallet/SDK usability + security
- [ ] Verify cv>=5 finality semantics alignment in SDK trustless path.
  - Files: `sdk/selfcoin-wallet-js/src/proofs/finality.ts`, `sdk/selfcoin-wallet-js/src/wallet/SelfCoinWallet.ts`.
  - Tests: cv5/cv6 integration vectors.
  - Launch blocker: **YES** if cv>=5 planned soon.

## 7) Observability/monitoring
- [ ] Add production metrics endpoint + alert contracts.
  - Files: `src/node/node.cpp`, `src/lightserver/server.cpp`, `scripts/observe.py`.
  - Tests: scrape/alert integration tests.
  - Launch blocker: **YES**.

## 8) Release/upgrade process
- [ ] Activation rollout SOP (canary/staging/abort criteria/mixed-version matrix).
  - Files: `mainnet/*.md`, `docs/*.md`.
  - Tests: scripted multi-node activation drill.
  - Launch blocker: **YES**.

---

## C) ADVERSARIAL THREAT MODEL SUMMARY

Top realistic attacks and current status:
- Tx/mempool flooding: partially mitigated (`src/mempool/mempool.cpp`) by size/count/fee checks.
- Invalid frame floods: mitigated (`src/p2p/framing.cpp`, `src/p2p/hardening.cpp`).
- Wrong-port/TLS misconfig floods: diagnosable and scored (`src/p2p/framing.cpp`, `src/node/node.cpp`).
- Eclipse/Sybil bootstrap attacks: partially mitigated (`src/p2p/addrman.cpp`, seed policy), still infra-sensitive.
- Cross-network injection: mitigated via magic/network_id/protocol checks (`src/p2p/framing.cpp`, `src/node/node.cpp`).
- Seed/entropy grinding pressure: partially mitigated by canonical entropy path (`src/consensus/validators.cpp`).
- Validator cartel/bribery pressure: partially mitigated by v4-v7 mechanisms; parameter quality is critical.
- Committee targeting: improved under v5 private sortition (if activated).
- Lightserver deception: mitigated in trustless SDK mode via finality+SMT proof checks.
- DB corruption/replay divergence: partially mitigated via genesis marker checks + deterministic replay paths; requires stronger torture testing.

Most likely first failures under adversarial real-world traffic:
1. Lightserver parsing/abuse path (until strict parser + rate limits).
2. P2P CPU pressure on expensive validation paths.
3. Bootstrap/peer diversity issues (seed infra + eclipse surface).
4. Activation boundary/operator misconfiguration during upgrades.

---

## D) WHAT’S LEFT TO LAUNCH MAINNET? (PR Plan)

## PR-L1 — Stability Gate: remove flaky crash
- Scope: make full test suite deterministic; add sanitizer CI gate.
- Files: `tests/*`, `src/node/node.cpp`, `src/p2p/peer_manager.cpp`, `CMakeLists.txt`.
- Acceptance:
  - `ctest` 100/100 loops pass.
  - ASan/UBSan clean.

## PR-L2 — Lightserver hardening
- Scope: strict JSON parser + request schema + rate limiting.
- Files: `src/lightserver/server.cpp`, `src/lightserver/server.hpp`.
- Acceptance:
  - malformed JSON tests pass.
  - abuse tests show bounded CPU/memory.

## PR-L3 — P2P anti-DoS hardening
- Scope: early-drop/budgeting for expensive verification paths.
- Files: `src/node/node.cpp`, `src/p2p/hardening.cpp`, `src/p2p/peer_manager.cpp`.
- Acceptance:
  - flood tests do not stall finalization loop.

## PR-L4 — Activation rollout discipline
- Scope: canary runbook, mixed-version matrix, rollback criteria.
- Files: `mainnet/THREAT_MODEL_AND_LAUNCH_CHECKLIST.md`, `docs/*.md`.
- Acceptance:
  - scripted activation rehearsal succeeds.

## PR-L5 — Observability baseline
- Scope: metrics + alerts for finality lag/quorum wait/identity mismatch.
- Files: node/lightserver + `scripts/observe.py`.
- Acceptance:
  - alert simulation triggers expected alarms.

## Minimum Viable Launch Definition
Before public genesis + broad release, all must be true:
- [ ] No flaky test/segfault in repeated full-suite runs.
- [ ] ASan/UBSan clean.
- [ ] Lightserver strict parser + rate limiting deployed.
- [ ] Multi-region seeds live and externally reachable.
- [ ] Monitoring/alerts live.
- [ ] Activation disabled at genesis (`cv1` launch mode).

---

## Exact Commands (Pass/Fail)

## Build + tests
```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

## Stability loop (100x full suite)
```bash
for i in $(seq 1 100); do
  echo "[loop] run $i"
  ctest --test-dir build --output-on-failure || break
done
```

## ASan/UBSan build
```bash
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSELFCOIN_SANITIZE=ON
cmake --build build-asan -j4
ctest --test-dir build-asan --output-on-failure
```

## cv1 genesis-mode local node (activation disabled)
```bash
./build/selfcoin-node --db ~/.selfcoin/mainnet-node1 --public
./build/selfcoin-node --db ~/.selfcoin/mainnet-node2 --peers 127.0.0.1:19440
./build/selfcoin-node --db ~/.selfcoin/mainnet-node3 --peers 127.0.0.1:19440
```

## Lightserver smoke checks
```bash
./build/selfcoin-lightserver --db ~/.selfcoin/mainnet-node1 --bind 127.0.0.1 --port 19444 --relay-host 127.0.0.1 --relay-port 19440
curl -s -X POST http://127.0.0.1:19444/rpc -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}'
curl -s -X POST http://127.0.0.1:19444/rpc -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_tip","params":{}}'
```

## Chain identity cross-check
```bash
./build/selfcoin-cli rpc_compare --urls http://127.0.0.1:19444/rpc,http://127.0.0.1:19445/rpc
```

---

## Release / Ops Requirements

## Seed node diversity
- At least 3 independent public seeds in different regions/operators.
- Publish only P2P endpoints on `:19440` in seeds lists.

## Firewall and exposure
- P2P node operators: open `19440/tcp` inbound.
- Lightserver operators: expose `19444` only when intended; default local bind for private use.

## Monitoring minimum
- Track: finalized height progress, peers in/out, addrman size, consensus_state, chain identity mismatch counters.
- Alert on: stalled finalization, low peer count, chain identity mismatch, repeated invalid-frame storms.

## Data directories and backups
- Default data root: `~/.selfcoin/mainnet`.
- Back up: DB directory + keystore (`~/.selfcoin/mainnet/keystore/validator.json`) securely.
- Never expose keystore files on public endpoints.

## Upgrade discipline
- Do not enable activation ad-hoc across mixed operators.
- Require published mixed-version matrix and rollout steps before enabling any cv increase.

